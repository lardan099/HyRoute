// Package uirpc connects HyRoute's window process to the main one. The
// window (Wails and WebView2) runs as a process of its own, started when
// the window opens and gone when it closes, so that WebView2's memory is
// freed while HyRoute sits in the tray; everything else (the engine, the
// tray, the controller) stays in the main process.
//
// The two talk over a pair of anonymous pipes the main process hands to
// the window process it starts: nothing else can open them. Either side
// can call the other (Call) and send events (Notify). A frame is a 4-byte
// little-endian length and a JSON object.
package uirpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
)

// MaxFrame bounds one frame. The largest answers are the connections list
// and a journal: a few megabytes.
const MaxFrame = 64 << 20

// ErrClosed: the other side is gone (the window closed, HyRoute exited).
var ErrClosed = errors.New("uirpc: closed")

type frame struct {
	T  string            `json:"t"` // "req", "res", "ev"
	ID uint64            `json:"id,omitempty"`
	M  string            `json:"m,omitempty"` // method or event name
	A  []json.RawMessage `json:"a,omitempty"` // arguments
	R  json.RawMessage   `json:"r,omitempty"` // result
	E  *string           `json:"e,omitempty"` // error text
}

// Handler answers a call from the other side.
type Handler func(method string, args []json.RawMessage) (any, error)

// Peer is one end of the connection. Set the handlers before Run.
type Peer struct {
	OnCall  Handler
	OnEvent func(name string, args []json.RawMessage)

	r   io.Reader
	w   io.Writer
	wmu sync.Mutex

	next atomic.Uint64
	mu   sync.Mutex
	wait map[uint64]chan frame
	gone bool
	done chan struct{}
}

func New(r io.Reader, w io.Writer) *Peer {
	return &Peer{r: r, w: w, wait: map[uint64]chan frame{}, done: make(chan struct{})}
}

// Done is closed once the connection ends.
func (p *Peer) Done() <-chan struct{} { return p.done }

// Run reads until the other side closes its end; calls waiting for an
// answer then fail with ErrClosed. Each call from the other side runs in a
// goroutine of its own.
func (p *Peer) Run() error {
	defer p.close()
	for {
		f, err := readFrame(p.r)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		switch f.T {
		case "req":
			go p.answer(f)
		case "res":
			p.mu.Lock()
			ch := p.wait[f.ID]
			delete(p.wait, f.ID)
			p.mu.Unlock()
			if ch != nil {
				ch <- f
			}
		case "ev":
			if p.OnEvent != nil {
				p.OnEvent(f.M, f.A)
			}
		}
	}
}

func (p *Peer) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gone {
		return
	}
	p.gone = true
	for id, ch := range p.wait {
		close(ch)
		delete(p.wait, id)
	}
	close(p.done)
}

func (p *Peer) answer(f frame) {
	res := frame{T: "res", ID: f.ID}
	var out any
	err := errors.New("uirpc: no handler")
	if p.OnCall != nil {
		out, err = safeCall(p.OnCall, f.M, f.A)
	}
	if err == nil {
		res.R, err = json.Marshal(out)
	}
	if err != nil {
		s := err.Error()
		res.E = &s
		res.R = nil
	}
	p.send(res)
}

// safeCall turns a panic of the handler into an error: one broken call
// must not end the process (the main one holds the engine).
func safeCall(h Handler, m string, a []json.RawMessage) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("внутренняя ошибка в %s: %v", m, r)
		}
	}()
	return h(m, a)
}

// Call calls method on the other side with args (each marshalled to
// JSON) and returns the result as JSON. An error the other side returned
// comes back with its text.
func (p *Peer) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	raw := make([]json.RawMessage, len(args))
	for i, a := range args {
		b, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		raw[i] = b
	}
	return p.CallRaw(ctx, method, raw)
}

// CallRaw is Call with the arguments already in JSON.
func (p *Peer) CallRaw(ctx context.Context, method string, args []json.RawMessage) (json.RawMessage, error) {
	id := p.next.Add(1)
	ch := make(chan frame, 1)
	p.mu.Lock()
	if p.gone {
		p.mu.Unlock()
		return nil, ErrClosed
	}
	p.wait[id] = ch
	p.mu.Unlock()
	if err := p.send(frame{T: "req", ID: id, M: method, A: args}); err != nil {
		p.forget(id)
		return nil, err
	}
	select {
	case f, ok := <-ch:
		if !ok {
			return nil, ErrClosed
		}
		if f.E != nil {
			return nil, errors.New(*f.E)
		}
		return f.R, nil
	case <-ctx.Done():
		p.forget(id)
		return nil, ctx.Err()
	}
}

func (p *Peer) forget(id uint64) {
	p.mu.Lock()
	delete(p.wait, id)
	p.mu.Unlock()
}

// Notify sends an event; it does not wait for the other side.
func (p *Peer) Notify(name string, args ...any) error {
	raw := make([]json.RawMessage, len(args))
	for i, a := range args {
		b, err := json.Marshal(a)
		if err != nil {
			return err
		}
		raw[i] = b
	}
	return p.send(frame{T: "ev", M: name, A: raw})
}

func (p *Peer) send(f frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return fmt.Errorf("uirpc: %s: %d bytes is too large", f.M, len(b))
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := p.w.Write(append(n[:], b...)); err != nil {
		return fmt.Errorf("%w: %v", ErrClosed, err)
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return frame{}, err
	}
	size := binary.LittleEndian.Uint32(n[:])
	if size > MaxFrame {
		return frame{}, fmt.Errorf("uirpc: a frame of %d bytes", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return frame{}, err
	}
	var f frame
	if err := json.Unmarshal(b, &f); err != nil {
		return frame{}, fmt.Errorf("uirpc: %w", err)
	}
	return f, nil
}

var errorType = reflect.TypeFor[error]()

// Dispatch answers calls with the exported methods of target, as Wails
// binds them: each argument is decoded from JSON into the parameter's type
// (a missing one is the zero value), the result is the first value that is
// not an error, and a non-nil error is the call's error.
func Dispatch(target any) Handler {
	v := reflect.ValueOf(target)
	return func(method string, args []json.RawMessage) (any, error) {
		if method == "" || method[0] < 'A' || method[0] > 'Z' {
			return nil, fmt.Errorf("нет такого вызова: %q", method)
		}
		m := v.MethodByName(method)
		if !m.IsValid() {
			return nil, fmt.Errorf("нет такого вызова: %q", method)
		}
		t := m.Type()
		if t.IsVariadic() {
			return nil, fmt.Errorf("вызов %s не поддерживается", method)
		}
		if len(args) > t.NumIn() {
			return nil, fmt.Errorf("%s: %d аргументов вместо %d", method, len(args), t.NumIn())
		}
		in := make([]reflect.Value, t.NumIn())
		for i := range in {
			p := reflect.New(t.In(i))
			if i < len(args) && len(args[i]) > 0 {
				if err := json.Unmarshal(args[i], p.Interface()); err != nil {
					return nil, fmt.Errorf("%s: аргумент %d: %w", method, i+1, err)
				}
			}
			in[i] = p.Elem()
		}
		var out any
		for _, r := range m.Call(in) {
			if r.Type() == errorType {
				if !r.IsNil() {
					return nil, r.Interface().(error)
				}
				continue
			}
			if out == nil {
				out = r.Interface()
			}
		}
		return out, nil
	}
}
