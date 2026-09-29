package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/ctl"
)

// failure is an outcome other than success: its code gives the exit code.
type failure struct {
	code  string
	msg   string
	lines []ctl.ErrorLine
	local bool // a bad command line: the help hint follows
}

func (f *failure) exit() int { return ctl.ExitCode(f.code) }

func fail(code, format string, a ...any) *failure {
	return &failure{code: code, msg: fmt.Sprintf(format, a...)}
}

const (
	msgNotRunning = "HyRoute не запущен. Запустить: hyroutectl start"
	msgImpostor   = "Канал HyRoute создан другой программой, а не HyRoute: команда не отправлена. Перезапустите HyRoute."
	msgBusy       = "HyRoute занят другими командами, повторите позже."
	msgDenied     = "HyRoute отказал в доступе: команды принимаются только от программ пользователя, запустившего HyRoute."
	msgOff        = "HyRoute запущен, но не принимает команды: «Настройки» → «Командная строка», интерфейс «Для опытных» (выключено или ошибка канала — там же причина)."
	msgOtherUser  = "HyRoute запущен другой учётной записью Windows. Команды принимаются только от неё и из окна администратора."
	msgDropped    = "Связь с HyRoute прервалась (HyRoute закрылся?)."
)

// busyWait is how long Dial retries a pipe whose instances are all busy.
const busyWait = 5 * time.Second

// connect finds the HyRoute to talk to and connects: its own
// user's pipe, waiting while it starts; another account's only from an
// elevated administrator.
func (c *client) connect(ctx context.Context) (net.Conn, uint32, *failure) {
	d := c.d
	target := c.inv.User
	if target == "" {
		target = d.SelfSID
	}
	announced := false
	deadline := time.Now().Add(c.timeout(30 * time.Second))
	for {
		conn, pid, err := d.Dial(ctl.PipeName(target), busyWait)
		switch {
		case err == nil:
			return conn, pid, nil
		case errors.Is(err, ctl.ErrImpostor):
			return nil, 0, fail(ctl.CodeImpostor, msgImpostor)
		case errors.Is(err, ctl.ErrBusy):
			return nil, 0, fail(ctl.CodeBusy, msgBusy)
		case errors.Is(err, ctl.ErrDenied):
			return nil, 0, fail(ctl.CodeDenied, msgDenied)
		case !errors.Is(err, ctl.ErrNotRunning):
			return nil, 0, fail(ctl.CodeDropped, "Не удалось связаться с HyRoute: %v", err)
		}
		st, _ := d.Probe(ctl.RunEventName(target))
		switch st {
		case ctl.RunStarting:
			if !announced && !c.inv.JSON {
				fmt.Fprintln(d.Stderr, "HyRoute запускается…")
				announced = true
			}
			if !time.Now().Before(deadline) {
				return nil, 0, fail(ctl.CodeStarting, "HyRoute не ответил за %d с после запуска.", int(c.timeout(30*time.Second)/time.Second))
			}
			select {
			case <-ctx.Done():
				return nil, 0, fail(ctl.CodeInterrupted, "")
			case <-time.After(d.Poll):
			}
			continue
		case ctl.RunSettled:
			return nil, 0, fail(ctl.CodeOff, msgOff)
		case ctl.RunForeign:
			return nil, 0, fail(ctl.CodeImpostor, msgImpostor)
		}
		if c.inv.User != "" {
			return nil, 0, fail(ctl.CodeNotRunning, msgNotRunning)
		}
		// Not ours: maybe another account's HyRoute.
		sids, _ := d.FindPipes()
		var others []string
		for _, s := range sids {
			if !strings.EqualFold(s, d.SelfSID) {
				others = append(others, s)
			}
		}
		switch {
		case len(others) == 0:
			return nil, 0, fail(ctl.CodeNotRunning, msgNotRunning)
		case !d.Admin:
			return nil, 0, fail(ctl.CodeOtherUser, msgOtherUser)
		case len(others) > 1:
			return nil, 0, fail(ctl.CodeUsage, "Запущено несколько HyRoute разных учётных записей: укажите --user=<SID> (%s).", strings.Join(others, ", "))
		}
		target = others[0]
	}
}
