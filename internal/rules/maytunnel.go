package rules

// MayTunnel reports whether the flow sub goes through the tunnel for some
// domain: one of the outcomes Evaluate weighs when the domain is unknown
// is Tunnel. The engine refuses such an IPv6 connection at its SYN while
// IPv6 is kept out of the tunnel, so that the application falls back to
// IPv4 before the connection is up.
func (s *Set) MayTunnel(sub Subject) bool {
	for _, r := range s.unknownOutcomes(sub) {
		if s.result(r).Action == Tunnel {
			return true
		}
	}
	return false
}
