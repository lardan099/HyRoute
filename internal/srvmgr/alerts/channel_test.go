package alerts

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

const (
	fakeToken  = "123456789:fake-telegram-token-AAAAAAAAAAAAAAAA"
	fakeHookey = "fake-webhook-signing-key-0123"
)

func field(err error) string {
	var fe *model.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		kind     model.ChannelKind
		settings string
		secret   string
		quiet    model.QuietHours
		field    string // "" valid
	}{
		{model.ChannelTelegram, `{"chatId":"-1001234"}`, fakeToken, model.QuietHours{}, ""},
		{model.ChannelTelegram, `{"chatId":"@alerts_channel","apiBase":"http://127.0.0.1:8081/"}`, fakeToken, model.QuietHours{}, ""},
		{model.ChannelTelegram, `{"chatId":"-1001234","apiBase":"http://bot.example.com"}`, fakeToken, model.QuietHours{}, "apiBase"},
		{model.ChannelTelegram, `{"chatId":"-1001234"}`, "", model.QuietHours{}, "secret"},
		{model.ChannelTelegram, `{"chatId":"-1001234"}`, "123:a/b", model.QuietHours{}, "secret"},
		{model.ChannelTelegram, `{"chatId":"chat; drop"}`, fakeToken, model.QuietHours{}, "chatId"},
		{model.ChannelTelegram, `{"chatId":"1","token":"x"}`, fakeToken, model.QuietHours{}, "settings"},
		{model.ChannelWebhook, `{"url":"https://hooks.example.com/hyroute"}`, fakeHookey, model.QuietHours{From: "23:00", To: "08:00", Zone: "Europe/Moscow"}, ""},
		{model.ChannelWebhook, `{"url":"http://192.0.2.10:8080/in"}`, fakeHookey, model.QuietHours{}, ""},
		{model.ChannelWebhook, `{"url":"https://user:pw@hooks.example.com/"}`, fakeHookey, model.QuietHours{}, "url"},
		{model.ChannelWebhook, `{"url":"ftp://hooks.example.com/"}`, fakeHookey, model.QuietHours{}, "url"},
		{model.ChannelWebhook, `{"url":"https://hooks.example.com/"}`, "short", model.QuietHours{}, "secret"},
		{model.ChannelWebhook, `{"url":"https://hooks.example.com/"}`, fakeHookey, model.QuietHours{From: "23:00"}, "quiet"},
		{model.ChannelWebhook, `{"url":"https://hooks.example.com/"}`, fakeHookey, model.QuietHours{From: "25:00", To: "08:00"}, "quiet"},
		{model.ChannelWebhook, `{"url":"https://hooks.example.com/"}`, fakeHookey, model.QuietHours{From: "23:00", To: "08:00", Zone: "Mars/Olympus"}, "quiet"},
		{model.ChannelSMTP, `{"host":"smtp.example.com","security":"starttls","username":"bot","from":"HyRoute <bot@example.com>","to":["a@example.com"]}`, "pw", model.QuietHours{}, ""},
		{model.ChannelSMTP, `{"host":"smtp.example.com","security":"starttls","username":"bot","from":"bot@example.com","to":["a@example.com"]}`, "", model.QuietHours{}, "secret"},
		{model.ChannelSMTP, `{"host":"smtp.example.com","security":"none","from":"bot@example.com","to":["a@example.com"]}`, "", model.QuietHours{}, "security"},
		{model.ChannelSMTP, `{"host":"127.0.0.1","security":"none","from":"bot@example.com","to":["a@example.com"]}`, "", model.QuietHours{}, ""},
		{model.ChannelSMTP, `{"host":"smtp.example.com","security":"tls","from":"bot@example.com","to":[]}`, "", model.QuietHours{}, "to"},
		{model.ChannelSMTP, `{"host":"smtp.example.com:25","security":"tls","from":"bot@example.com","to":["a@example.com"]}`, "", model.QuietHours{}, "host"},
		{model.ChannelSMTP, `{"host":"smtp.example.com","security":"tls","from":"not an address","to":["a@example.com"]}`, "", model.QuietHours{}, "from"},
	} {
		c := model.AlertChannel{Name: " Канал ", Kind: tc.kind, Settings: json.RawMessage(tc.settings), Quiet: tc.quiet,
			Events: []model.EventKind{model.EventServer, model.EventServer, model.EventDisk}}
		err := Check(&c, tc.secret)
		if got := field(err); got != tc.field || (tc.field != "" && err == nil) {
			t.Errorf("%s %s: field %q (%v), want %q", tc.kind, tc.settings, got, err, tc.field)
			continue
		}
		if err == nil && (c.Name != "Канал" || len(c.Events) != 2) {
			t.Errorf("not normalized: %+v", c)
		}
	}
	// Defaults: the port of the security, the API base not stored, the
	// address alone.
	c := model.AlertChannel{Name: "m", Kind: model.ChannelSMTP, Settings: json.RawMessage(`{"host":"smtp.example.com","security":"tls","from":"HyRoute <bot@example.com>","to":["Admin <a@example.com>"]}`)}
	if err := Check(&c, ""); err != nil || string(c.Settings) != `{"host":"smtp.example.com","port":465,"security":"tls","from":"bot@example.com","to":["a@example.com"]}` {
		t.Fatalf("smtp %s %v", c.Settings, err)
	}
	c = model.AlertChannel{Name: "t", Kind: model.ChannelTelegram, Settings: json.RawMessage(`{"chatId":"1","apiBase":"https://api.telegram.org/"}`)}
	if err := Check(&c, fakeToken); err != nil || string(c.Settings) != `{"chatId":"1"}` {
		t.Fatalf("telegram %s %v", c.Settings, err)
	}
	if err := Check(&model.AlertChannel{Name: "x", Kind: model.ChannelWebhook, Settings: json.RawMessage(`{"url":"https://x.example.com"}`), Events: []model.EventKind{"weather"}}, fakeHookey); field(err) != "events" {
		t.Fatalf("unknown kind: %v", err)
	}
}

func TestQuiet(t *testing.T) {
	night := model.QuietHours{From: "23:00", To: "08:00", Zone: "Europe/Moscow"} // UTC+3
	day := model.QuietHours{From: "13:00", To: "14:30", Zone: "UTC"}
	at := func(h, m int) time.Time { return time.Date(2026, 9, 1, h, m, 0, 0, time.UTC) }
	for _, tc := range []struct {
		q    model.QuietHours
		t    time.Time
		want bool
	}{
		{night, at(20, 0), true},   // 23:00 MSK
		{night, at(19, 59), false}, // 22:59 MSK
		{night, at(1, 0), true},    // 04:00 MSK
		{night, at(4, 59), true},   // 07:59 MSK
		{night, at(5, 0), false},   // 08:00 MSK
		{day, at(13, 0), true},
		{day, at(14, 29), true},
		{day, at(14, 30), false},
		{day, at(12, 59), false},
		{model.QuietHours{}, at(3, 0), false},
	} {
		if got := quiet(tc.q, tc.t); got != tc.want {
			t.Errorf("%+v at %s: %v, want %v", tc.q, tc.t.Format("15:04"), got, tc.want)
		}
	}
}

func notice(id int64, kind model.EventKind, text string, closed bool) events.Notice {
	e := model.Event{ID: id, Kind: kind, Severity: model.SeverityWarning, Text: text, Count: 1, OpenedAt: time.Unix(1_790_000_000, 0)}
	if closed {
		e.ClosedAt, e.CloseText = e.OpenedAt.Add(time.Minute), "прошло: "+text
	}
	return events.Notice{Event: e, Closed: closed}
}

func TestRender(t *testing.T) {
	at := time.Unix(1_790_000_000, 0)
	m := render([]events.Notice{notice(1, model.EventServer, "Сервер «A» недоступен.", false)}, 0, at)
	if m.Text != "HyRoute Server. Проблема: Сервер «A» недоступен." || m.Subject != "HyRoute Server: Проблема: Сервер «A» недоступен." {
		t.Fatalf("one: %+v", m)
	}
	m = render([]events.Notice{
		notice(1, model.EventServer, "A", false),
		notice(2, model.EventDisk, "B", false),
		notice(1, model.EventServer, "A", true),
		notice(3, model.EventJob, "C", true),
	}, 2, at)
	want := "HyRoute Server — 5 событий:\n• Было и прошло: A → прошло: A\n• Проблема: B\n• Решено: прошло: C\nЕщё 2 события не отправлено: очередь канала была полна."
	if m.Text != want || m.Subject != "HyRoute Server: 5 событий" {
		t.Fatalf("glued:\n%s\nwant\n%s", m.Text, want)
	}
	var many []events.Notice
	for i := range 40 {
		many = append(many, notice(int64(i+1), model.EventServer, "x", false))
	}
	m = render(many, 0, at)
	if strings.Count(m.Text, "\n• ") != maxLines || !strings.HasSuffix(m.Text, "…и ещё 10.") {
		t.Fatalf("many: %s", m.Text)
	}
}
