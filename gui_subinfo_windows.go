//go:build windows

package main

import "errors"

// OpenSubscriptionSupport opens the support link the panel of subscription
// id sent, in the user's browser through the running Explorer (unelevated).
// The page names the subscription, never passes a URL, and there is no
// fallback to starting a browser from this elevated process: the link is on
// screen with «Скопировать» (CopyText) instead.
func (g *GUI) OpenSubscriptionSupport(id string) error {
	u, err := g.ctl.SupportLink(id)
	if err != nil {
		return err
	}
	if err := shellExecuteInExplorer(u); err != nil {
		g.ctl.Log.Warn("cannot open a support link through Explorer", "err", err)
		return errors.New("не удалось открыть ссылку в браузере. Скопируйте её")
	}
	return nil
}
