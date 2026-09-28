package ctl

// Kernel object names. Named pipes and Global\ events share one namespace
// across sessions: the owner's SID keeps users apart, and a hyroutectl in
// any session of the same user (SSH included) finds its HyRoute.

// PipePrefix starts the control pipe's name; the owner SID follows.
const PipePrefix = `HyRoute-7f3c1a52-ctl-`

// PipeName is the control pipe of the owner with sid.
func PipeName(sid string) string { return `\\.\pipe\` + PipePrefix + sid }

// RunEventName is the run event of the owner with sid: present while that
// user's HyRoute runs, signalled once its command line has settled.
func RunEventName(sid string) string { return `Global\HyRoute-7f3c1a52-run-` + sid }

// RunState is what a run event says about HyRoute.
type RunState int

const (
	RunAbsent   RunState = iota // no HyRoute of this user runs
	RunStarting                 // it runs, its command line is not up yet
	RunSettled                  // its command line settled (listening, off or failed)
	RunForeign                  // the event was created by another program
)
