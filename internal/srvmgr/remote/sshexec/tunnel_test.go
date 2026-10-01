package sshexec

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
)

// The server's loopback through the SSH connection: what listens on
// 127.0.0.1 there answers (the test server's loopback is this machine's).
func TestDialLoopback(t *testing.T) {
	srv := sshtest.Start(t, "tester", fakePass)
	c := dial(t, srv, Auth{Password: fakePass})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(conn, conn)
		conn.Close()
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	conn, err := remote.DialLoopback(context.Background(), c, port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "ping" {
		t.Fatalf("%q %v", b, err)
	}
	// Nothing listens: the server refuses the channel.
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	freePort := free.Addr().(*net.TCPAddr).Port
	free.Close()
	if _, err := c.DialLoopback(context.Background(), freePort); err == nil {
		t.Fatal("a closed port opened")
	}
	if _, err := c.DialLoopback(context.Background(), 70000); err == nil {
		t.Fatal("port " + strconv.Itoa(70000))
	}
	// An executor without a tunnel says so.
	if _, err := remote.DialLoopback(context.Background(), fake.New(), port); !errors.Is(err, remote.ErrNoTunnel) {
		t.Fatalf("fake: %v", err)
	}
}
