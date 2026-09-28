package ctlserver

import (
	"encoding/json"
	"time"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/groups"
)

// App types → wire DTOs. The DTOs are whitelists: only the fields listed
// here cross the pipe, so a new secret field in an app type never leaks.

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func raw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func statusView(st app.Status, version string) ctl.StatusView {
	v := ctl.StatusView{App: version, State: st.State, Message: st.Message, Since: rfc3339(st.Since), GroupsNote: st.GroupsNote,
		KillSwitch: st.KillSwitch, KillSwitchError: st.KillSwitchError, NoTunnel: st.NoTunnel, LoadError: st.LoadError,
		SettingsRev: st.SettingsRev, Tunnels: []ctl.TunnelView{}, Warnings: []string{}}
	if st.MainID != "" {
		v.Main = &ctl.TargetView{Kind: targetKind(st.MainID), ID: st.MainID, Name: st.Main}
	}
	if st.MainGroup != nil {
		v.MainGroup = raw(st.MainGroup)
	}
	if st.Ruleset.ID != "" {
		v.Ruleset = &ctl.RulesetBrief{ID: st.Ruleset.ID, Name: st.Ruleset.Name, Count: st.Ruleset.Count}
	}
	if st.Net != nil {
		// netmodes' NetState (the caller masks it for --private).
		v.Net = raw(st.Net)
	}
	if st.DNS != nil {
		// dns' DNSStatus: preset names and server IDs, never a URL.
		v.DNS = raw(st.DNS)
	}
	if len(st.SubAlerts) > 0 {
		v.SubAlerts = raw(st.SubAlerts)
	}
	if st.Stats != nil {
		// Counters only (session.Stats), dns' dns* counters among them.
		v.Stats = raw(st.Stats)
	}
	for _, t := range st.Tunnels {
		// SOCKS ports and server IPs stay inside.
		v.Tunnels = append(v.Tunnels, ctl.TunnelView{ID: t.ID, Name: t.Name, State: t.State, Message: t.Message,
			Restarts: t.Restarts, Rejected: t.Rejected, Sent: t.Sent, Recv: t.Recv})
	}
	for _, w := range st.Warnings {
		v.Warnings = append(v.Warnings, w.Text)
	}
	return v
}

func serverViews(ps []app.ProfileSummary, st app.Status) []ctl.ServerView {
	state := map[string]string{}
	for _, t := range st.Tunnels {
		state[t.ID] = t.State
	}
	out := make([]ctl.ServerView, 0, len(ps))
	for _, p := range ps {
		out = append(out, ctl.ServerView{ID: p.ID, Name: p.Name, Address: p.Server, Source: p.SourceName, Main: p.Main,
			Missing: p.Missing, State: state[p.ID]})
	}
	return out
}

func groupsView(info app.GroupsInfo) ctl.GroupsView {
	v := ctl.GroupsView{Groups: []ctl.GroupLine{}, LoadError: info.LoadError}
	for _, g := range info.Groups {
		l := ctl.GroupLine{ID: g.ID, Name: g.Name, Strategy: string(g.Strategy), Active: g.Active, Main: g.Main, Running: g.Running,
			Up: g.Up, Total: len(g.Members), Rejected: g.Rejected, Members: []ctl.MemberLine{}}
		for _, m := range g.Views {
			if m.ID == g.Active {
				l.ActiveName = m.Name
			}
			l.Members = append(l.Members, ctl.MemberLine{ID: m.ID, Name: m.Name, State: m.State, ProbeError: m.ProbeError,
				Reason: m.Reason, LatencyMs: m.LatencyMs, Errors: m.Errors, Skipped: m.Skipped, Missing: m.Missing})
		}
		v.Groups = append(v.Groups, l)
	}
	return v
}

func checkView(r app.CheckResult) ctl.CheckView {
	v := ctl.CheckView{Profile: r.Profile, OK: r.OK, ExternalIP: r.ExternalIP, LatencyMs: r.LatencyMs, Steps: []ctl.CheckStep{}}
	for _, s := range r.Steps {
		v.Steps = append(v.Steps, ctl.CheckStep{Name: s.Name, OK: s.OK, Skip: s.Skip, Detail: s.Detail, Ms: s.Ms})
	}
	return v
}

func rulesetsView(r app.RulesetsView) ctl.RulesetsView {
	v := ctl.RulesetsView{Active: r.Active, Saved: r.Saved, Error: r.Error, List: []ctl.RulesetLine{}}
	for _, e := range r.List {
		v.List = append(v.List, ctl.RulesetLine{ID: e.ID, Name: e.Name, Rules: e.Rules, DefaultAction: e.DefaultAction.String(),
			Active: e.Active, Warnings: e.Warnings, Error: e.Error})
	}
	return v
}

// subLines never carries the URL: SubLine has no field for it.
func subLines(subs []app.SubView) []ctl.SubLine {
	out := make([]ctl.SubLine, 0, len(subs))
	for _, s := range subs {
		l := ctl.SubLine{ID: s.ID, Name: s.Name, Enabled: s.Enabled, Profiles: s.Profiles, Missing: s.Missing,
			UpdatedAt: rfc3339(s.LastUpdate), LastError: s.LastError}
		if s.Enabled {
			l.NextAt = rfc3339(s.NextAt)
		}
		if s.Info != nil {
			l.Summary = s.Info.Summary
		}
		out = append(out, l)
	}
	return out
}

// dnsExplainView is dns' DNSExplain with the server or group named: the
// client cannot resolve an ID.
type dnsExplainView struct {
	app.DNSExplain
	ProfileName string          `json:"profileName,omitempty"`
	System      *dnsExplainView `json:"system,omitempty"`
}

// explainResult is app.Explanation with its DNS line's target named.
type explainResult struct {
	app.Explanation
	DNS *dnsExplainView `json:"dns,omitempty"`
}

func dnsExplain(d *app.DNSExplain, name func(string) string) *dnsExplainView {
	if d == nil {
		return nil
	}
	v := &dnsExplainView{DNSExplain: *d, System: dnsExplain(d.System, name)}
	v.DNSExplain.System = nil
	if d.Route == "tunnel" && d.Profile != "" {
		// As the window's profileName: a target gone since.
		switch v.ProfileName = name(d.Profile); {
		case v.ProfileName != "":
		case groups.IsGroupID(d.Profile):
			v.ProfileName = "удалённая группа"
		default:
			v.ProfileName = "удалённый сервер"
		}
	}
	return v
}

func explainView(ex app.Explanation, name func(string) string) explainResult {
	return explainResult{Explanation: ex, DNS: dnsExplain(ex.DNS, name)}
}
