package ctlserver

import (
	"errors"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/ctl"
)

// The browser extension's commands (browser/; hyroutectl is its native
// messaging host and passes them on unchanged). The controller logs the
// edits itself, without the sites.

func cmdBrowserInfo(r *request, a any) (any, *ctl.Error) {
	info, err := r.s.api.BrowserInfo(*a.(*app.BrowserQuery))
	if err != nil {
		return nil, browserError(err)
	}
	return info, nil
}

func cmdBrowserAdd(r *request, a any) (any, *ctl.Error) {
	if e := r.live(); e != nil {
		return nil, e
	}
	res, err := r.s.api.BrowserAdd(*a.(*app.BrowserEdit))
	if err != nil {
		return nil, browserError(err)
	}
	return res, nil
}

func cmdBrowserRemove(r *request, a any) (any, *ctl.Error) {
	if e := r.live(); e != nil {
		return nil, e
	}
	res, err := r.s.api.BrowserRemove(*a.(*app.BrowserEdit))
	if err != nil {
		return nil, browserError(err)
	}
	return res, nil
}

func browserError(err error) *ctl.Error {
	if errors.Is(err, app.ErrBrowserOff) {
		return browserOffError
	}
	return failed("%s", capital(err.Error()))
}
