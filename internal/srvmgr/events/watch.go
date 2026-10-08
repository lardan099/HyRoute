package events

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// DefaultThreshold is how many checks in a row change the status an event
// tells: one bad check is not an outage, one good one not a recovery.
const DefaultThreshold = 3

// A disk is full above diskFull percent and fine again below diskFine:
// a disk at the edge does not open and close an event every minute.
const (
	diskFull = 90.0
	diskFine = 85.0
)

// Watcher turns signals into events on Bus: the monitor's rounds
// (monitor.Events), link checks (cascade.LinkEvents), jobs that end
// (jobs.Engine.OnEnd), SSH logins (connect.Events) and geo updates. The
// drift check of P4-06 raises and closes its events with Drift and
// DriftGone.
type Watcher struct {
	Bus *Bus
	// Threshold: a status of a server or a link counts once it was seen
	// this many times in a row (DefaultThreshold if 0).
	Threshold int

	mu      sync.Mutex
	streaks map[string]streak
	disk    map[int64]bool // full when last seen
}

// streak is the status seen in a row under a key.
type streak struct {
	status model.ServerState
	n      int
	// told is the text the event got last ("": not raised in this
	// streak).
	told string
}

func (w *Watcher) threshold() int {
	if w.Threshold <= 0 {
		return DefaultThreshold
	}
	return w.Threshold
}

// count records status under key and reports whether it is confirmed:
// seen Threshold times in a row or more. first: just now.
func (w *Watcher) count(key string, status model.ServerState) (confirmed, first bool, told string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.streaks == nil {
		w.streaks = map[string]streak{}
	}
	s := w.streaks[key]
	if s.status != status {
		s = streak{status: status}
	}
	s.n++
	w.streaks[key] = s
	n := w.threshold()
	return s.n >= n, s.n == n, s.told
}

// tell records the text raised under key.
func (w *Watcher) tell(key, text string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.streaks[key]
	s.told = text
	w.streaks[key] = s
}

// Server hears a server's status from a monitoring round (healthy,
// degraded or offline). A status other than healthy, seen Threshold times
// in a row, opens the server's event (a new reason while it lasts updates
// it); healthy as many times closes it.
func (w *Watcher) Server(ctx context.Context, srv model.Server, status model.ServerState, reason string) {
	key := "server:" + strconv.FormatInt(srv.ID, 10)
	confirmed, first, told := w.count(key, status)
	if !confirmed {
		return
	}
	if status == model.StateHealthy {
		if first {
			w.Bus.Resolve(ctx, key, "Сервер «"+srv.Name+"» снова работает.")
		}
		return
	}
	text := "Сервер «" + srv.Name + "» "
	sev := model.SeverityWarning
	switch status {
	case model.StateOffline:
		text += "недоступен."
		sev = model.SeverityCritical
	default:
		text += "работает с проблемами."
	}
	if reason != "" {
		text += " " + reason
	}
	if text == told && !first {
		return
	}
	if w.Bus.Raise(ctx, model.Event{Kind: model.EventServer, Key: key, Severity: sev, Subject: model.SubjectServer, SubjectID: srv.ID, Text: text}) == nil {
		w.tell(key, text)
	}
}

// Link hears a check of a cascade link from its entry: offline or
// degraded Threshold times in a row opens the link's event, healthy as
// many times closes it.
func (w *Watcher) Link(ctx context.Context, chain model.Chain, l model.ChainLink, entry, exit model.Server, c model.LinkCheck) {
	key := "link:" + strconv.FormatInt(chain.ID, 10) + ":" + strconv.Itoa(l.Idx)
	confirmed, first, told := w.count(key, c.Status)
	if !confirmed {
		return
	}
	what := "Каскад «" + chain.Name + "»: связь «" + entry.Name + "» → «" + exit.Name + "» "
	if c.Status == model.StateHealthy {
		if first {
			w.Bus.Resolve(ctx, key, what+"снова работает.")
		}
		return
	}
	text, sev := what+"не работает.", model.SeverityCritical
	if c.Status == model.StateDegraded {
		text, sev = what+"работает с проблемами.", model.SeverityWarning
	}
	if c.Reason != "" {
		text += " " + capitalize(c.Reason) + "."
	}
	if text == told && !first {
		return
	}
	if w.Bus.Raise(ctx, model.Event{Kind: model.EventLink, Key: key, Severity: sev, Subject: model.SubjectChain, SubjectID: chain.ID, Text: text}) == nil {
		w.tell(key, text)
	}
}

// Disk hears how full a server's root file system is: above 90 % opens
// the server's disk event, below 85 % closes it.
func (w *Watcher) Disk(ctx context.Context, srv model.Server, usedKiB, totalKiB uint64) {
	if totalKiB == 0 {
		return
	}
	pct := 100 * float64(usedKiB) / float64(totalKiB)
	w.mu.Lock()
	if w.disk == nil {
		w.disk = map[int64]bool{}
	}
	full, known := w.disk[srv.ID]
	var raise, resolve bool
	switch {
	case pct > diskFull && (!known || !full):
		w.disk[srv.ID], raise = true, true
	case pct < diskFine && (!known || full):
		w.disk[srv.ID], resolve = false, true
	}
	w.mu.Unlock()
	key := "disk:" + strconv.FormatInt(srv.ID, 10)
	free := Size(totalKiB - min(usedKiB, totalKiB))
	switch {
	case raise:
		w.Bus.Raise(ctx, model.Event{Kind: model.EventDisk, Key: key, Severity: model.SeverityWarning, Subject: model.SubjectServer, SubjectID: srv.ID,
			Text: fmt.Sprintf("Диск сервера «%s» заполнен на %.0f %%: свободно %s.", srv.Name, pct, free)})
	case resolve:
		w.Bus.Resolve(ctx, key, fmt.Sprintf("На диске сервера «%s» снова есть место: заполнен на %.0f %%.", srv.Name, pct))
	}
}

// Size is a size in KiB for people: «812 МБ», «1,4 ГБ».
func Size(kib uint64) string {
	switch {
	case kib >= 1<<20:
		return strings.Replace(strconv.FormatFloat(float64(kib)/(1<<20), 'f', 1, 64), ".", ",", 1) + " ГБ"
	case kib >= 1<<10:
		return strconv.FormatUint(kib>>10, 10) + " МБ"
	}
	return strconv.FormatUint(kib, 10) + " КБ"
}

// Network hears whether the controller itself has network (the monitor
// asks when no server answered a round).
func (w *Watcher) Network(ctx context.Context, online bool) {
	if online {
		w.Bus.Resolve(ctx, NetworkKey, "Сеть у controller снова есть.")
		return
	}
	w.Bus.Raise(ctx, model.Event{Kind: model.EventNetwork, Key: NetworkKey, Severity: model.SeverityCritical, Subject: model.SubjectController,
		Text: "У controller нет сети: ни один сервер не ответил, общедоступные адреса тоже недоступны. Состояния серверов не меняются, пока сеть не вернётся."})
}

// NetworkKey is the key of the event «the controller has no network».
const NetworkKey = "network"

// Kinds of jobs for people (the same as the admin's «kind.*»).
var kindNames = map[string]string{
	"preflight": "Проверка сервера",
	"deploy":    "Развёртывание",
	"import":    "Импорт",
	"service":   "Управление службой",
	"apply":     "Применение конфига",
	"maintain":  "Обслуживание Hysteria",
	"tuning":    "Системные настройки",
	"link":      "Развёртывание связи каскада",
	"unlink":    "Снятие связи каскада",
	"geo":       "Установка баз geo",
}

// KindName is a job kind for people.
func KindName(kind string) string {
	if n, ok := kindNames[kind]; ok {
		return n
	}
	return kind
}

// JobEnded hears a job that completed or failed. A failure opens the
// event of its kind on its server (repeats glue into it), a success of
// the same kind closes it; a server the job left needing attention gets
// that event, one that no longer needs it gets it closed.
func (w *Watcher) JobEnded(ctx context.Context, j model.Job) {
	label := KindName(j.Kind)
	where := ""
	if j.ServerID != 0 {
		if srv, err := w.Bus.Store.ServerByID(ctx, j.ServerID); err == nil {
			where = " на сервере «" + srv.Name + "»"
		}
	}
	key := "job:" + j.Kind + ":" + strconv.FormatInt(j.ServerID, 10)
	switch j.State {
	case model.JobFailed:
		text := "Задание «" + label + "»" + where + " не выполнено."
		if j.ErrorMessage != "" && j.ErrorMessage != "Задание не выполнено." {
			text += " " + j.ErrorMessage
		}
		w.Bus.Raise(ctx, model.Event{Kind: model.EventJob, Key: key, Severity: model.SeverityWarning, Subject: model.SubjectJob, SubjectID: j.ID, Text: text})
	case model.JobCompleted:
		w.Bus.Resolve(ctx, key, "Задание «"+label+"»"+where+" выполнено.")
	}
	for _, id := range j.AllServers() {
		srv, err := w.Bus.Store.ServerByID(ctx, id)
		if err != nil {
			continue
		}
		akey := AttentionKey(id)
		if srv.State != model.StateNeedsAttention {
			w.Bus.Resolve(ctx, akey, "Сервер «"+srv.Name+"» больше не требует внимания.")
			continue
		}
		text := "Сервер «" + srv.Name + "» требует внимания после задания «" + label + "»: проверьте его и заметки сервера."
		if j.ErrorMessage != "" && j.State == model.JobFailed {
			text += " " + j.ErrorMessage
		}
		w.Bus.Raise(ctx, model.Event{Kind: model.EventAttention, Key: akey, Severity: model.SeverityCritical, Subject: model.SubjectServer, SubjectID: id, Text: text})
	}
}

// AttentionKey is the key of the event «the server needs attention».
func AttentionKey(serverID int64) string { return "attention:" + strconv.FormatInt(serverID, 10) }

// SSH hears how a login to a server went (connect.Connector): another
// host key or a refused login opens its event, a login that worked
// closes both.
func (w *Watcher) SSH(ctx context.Context, serverID int64, err error) {
	hk, auth := "host_key:"+strconv.FormatInt(serverID, 10), "ssh_auth:"+strconv.FormatInt(serverID, 10)
	var changed *remote.HostKeyChangedError
	isChanged, refused := errors.As(err, &changed), errors.Is(err, remote.ErrAuthFailed)
	if err != nil && !isChanged && !refused {
		return // unreachable, a timeout: the status tells
	}
	if err == nil && !w.Bus.IsOpen(ctx, hk) && !w.Bus.IsOpen(ctx, auth) {
		return // the usual login: nothing to close
	}
	srv, serr := w.Bus.Store.ServerByID(ctx, serverID)
	if serr != nil {
		return
	}
	switch {
	case err == nil:
		w.Bus.Resolve(ctx, hk, "Ключ SSH сервера «"+srv.Name+"» снова подтверждён.")
		w.Bus.Resolve(ctx, auth, "Сервер «"+srv.Name+"» снова принимает вход по SSH.")
	case isChanged:
		w.Bus.Raise(ctx, model.Event{Kind: model.EventHostKey, Key: hk, Severity: model.SeverityCritical, Subject: model.SubjectServer, SubjectID: serverID,
			Text: "Сервер «" + srv.Name + "» предъявил другой ключ SSH. Это бывает после переустановки системы — или при перехвате соединения. Панель к нему не подключается, пока ключ не подтвердят заново на странице сервера."})
	case refused:
		w.Bus.Raise(ctx, model.Event{Kind: model.EventSSHAuth, Key: auth, Severity: model.SeverityWarning, Subject: model.SubjectServer, SubjectID: serverID,
			Text: "Сервер «" + srv.Name + "» отклонил вход по SSH: проверьте пользователя, пароль или ключ."})
	}
}

// GeoKey is the key of the event «the controller's geo databases were not
// updated».
const GeoKey = "geo"

// Geo hears an update of the controller's geo databases (geo.Store): a
// failure opens the event, an update that worked closes it.
func (w *Watcher) Geo(ctx context.Context, release string, err error) {
	if err == nil {
		w.Bus.Resolve(ctx, GeoKey, "Базы geo controller обновлены: релиз "+release+".")
		return
	}
	w.Bus.Raise(ctx, model.Event{Kind: model.EventGeo, Key: GeoKey, Severity: model.SeverityWarning, Subject: model.SubjectController,
		Text: "Базы geo controller не обновились: " + err.Error() + ". Серверы получат новые базы после следующего удачного обновления."})
}

// Drift opens the event of a server changed outside HyRoute (P4-06):
// what says what differs, in short and without secrets (it is cleaned
// as any text).
func (w *Watcher) Drift(ctx context.Context, srv model.Server, what string) {
	text := "Сервер «" + srv.Name + "» изменён вне HyRoute."
	if what != "" {
		text += " " + what
	}
	w.Bus.Raise(ctx, model.Event{Kind: model.EventDrift, Key: DriftKey(srv.ID), Severity: model.SeverityWarning, Subject: model.SubjectServer, SubjectID: srv.ID, Text: text})
}

// DriftGone closes it: the server is as HyRoute wrote it again.
func (w *Watcher) DriftGone(ctx context.Context, srv model.Server) {
	w.Bus.Resolve(ctx, DriftKey(srv.ID), "Сервер «"+srv.Name+"» снова совпадает с тем, что записала панель.")
}

// DriftKey is the key of a server's drift event.
func DriftKey(serverID int64) string { return "drift:" + strconv.FormatInt(serverID, 10) }

// capitalize upper-cases the first letter of a reason.
func capitalize(s string) string {
	for i, r := range s {
		return strings.ToUpper(string(r)) + s[i+len(string(r)):]
	}
	return s
}
