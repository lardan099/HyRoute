package deploy

// For the end-to-end test in package deploy_test: the simulated VPS.

// SimVPS is the simulated Debian server of the deploy tests.
type SimVPS = sim

// NewSimVPS returns a fresh simulated server.
func NewSimVPS() *SimVPS { return newSim() }

// AddDownload makes url downloadable on the server (curl).
func (s *sim) AddDownload(url string, b []byte) {
	s.mu.Lock()
	s.downloads[url] = b
	s.mu.Unlock()
}

// FileContent is a file of the server.
func (s *sim) FileContent(p string) ([]byte, bool) { return s.file(p) }

// ServiceState is the state of the Hysteria service.
func (s *sim) ServiceState() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}
