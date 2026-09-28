//go:build windows

package main

import "github.com/lardan099/hyroute/internal/stats"

// Traffic statistics («Статистика»).

// Stats is the report of a period: today, yesterday, 7d, 30d or YYYY-MM.
func (g *GUI) Stats(period string) (stats.Report, error) { return g.ctl.Stats(period) }

// ResetStats deletes every statistic («Сбросить статистику»).
func (g *GUI) ResetStats() error { return g.ctl.ResetStats() }

// SetStatsMode sets the collection mode: "" (all), "no-sites" or "off".
func (g *GUI) SetStatsMode(mode string) error { return g.ctl.SetStatsMode(mode) }
