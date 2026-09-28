package app

// Hooks of «Сети» (netmodes) that rule profiles call. Until netmodes
// lands they do nothing; netmodes deletes this file and defines both.

// netManual records that the user chose by hand (a switch of the rule
// profile from the window, the tray or the CLI): it wins over the network
// rules until the next network change. Called holding no lock.
func (c *Controller) netManual() {}

// NetRulesUsing names the network rules whose action switches to rule
// profile id (shown in the delete confirmation). Takes its own lock.
func (c *Controller) NetRulesUsing(id string) []string { return nil }
