package app

// Source says who asked for an action: the user (window, tray, CLI) or an automatic rule.
type Source string

const (
	SourceUser    Source = "user" // window
	SourceTray    Source = "tray"
	SourceCLI     Source = "cli"
	SourceNetwork Source = "network" // netmodes
)
