//go:build windows

package ctl

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// fileConn is a net.Conn over an *os.File holding an overlapped pipe
// handle: the runtime does the I/O, deadlines and cancellation. Close is
// f.Close only: DisconnectNamedPipe would discard data the peer has not
// read yet.
type fileConn struct {
	f    *os.File
	name string
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

// eofErr maps the ways a pipe reports its other end gone to io.EOF.
func eofErr(err error) error {
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) ||
		errors.Is(err, windows.ERROR_NO_DATA) {
		return io.EOF
	}
	return err
}

func (c *fileConn) Read(b []byte) (int, error) {
	n, err := c.f.Read(b)
	return n, eofErr(err)
}

func (c *fileConn) Write(b []byte) (int, error) {
	n, err := c.f.Write(b)
	return n, eofErr(err)
}

func (c *fileConn) Close() error                       { return c.f.Close() }
func (c *fileConn) LocalAddr() net.Addr                { return pipeAddr(c.name) }
func (c *fileConn) RemoteAddr() net.Addr               { return pipeAddr(c.name) }
func (c *fileConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *fileConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *fileConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }
