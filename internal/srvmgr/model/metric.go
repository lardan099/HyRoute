package model

import "time"

// Metric is one point of a server's monitoring: a sample (Step 0) or the
// average over Step seconds starting at At. Rates are nil when they
// cannot be known (the first sample, a reboot in between).
type Metric struct {
	ServerID int64
	At       time.Time
	Step     int // 0: a sample; MetricStep: an aggregate
	// CPU is the busy share of all cores, 0–100.
	CPU          *float64
	MemUsedMiB   float64 // total minus available
	MemTotalMiB  float64
	DiskUsedMiB  float64 // the filesystem of /
	DiskTotalMiB float64
	Load1        float64
	// RxBps and TxBps are bytes per second through the real interfaces.
	RxBps, TxBps *float64
}

// MetricStep is the length of an aggregate, in seconds.
const MetricStep = 900
