package cli

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/ctl"
)

// The browser extension's native messaging host. A Chromium browser starts
// hyroutectl with the extension's origin as the first argument and talks
// over stdin and stdout: each message is a uint32 length in the machine's
// byte order (little-endian on Windows) and that many bytes of UTF-8 JSON.
// A message is a request {id, cmd, args}; the answer {id, ok, result} or
// {id, ok: false, code, error}. Only ctl.BrowserCommands go on to HyRoute,
// the same way any hyroutectl command does.

// Native messaging limits: the browser refuses a message to it over 1 MB;
// requests are much smaller than what Chrome allows (64 MB).
const (
	maxNativeIn  = 1 << 20
	maxNativeOut = 1 << 20
)

const msgBrowserOff = "Расширение для браузера выключено в HyRoute: «Настройки» → «Расширение для браузера»"

// nativeTimeout bounds one request, waiting for a starting HyRoute
// included.
const nativeTimeout = 20 * time.Second

// IsNativeHost reports a start by a browser: the first argument is an
// extension origin.
func IsNativeHost(argv []string) bool {
	return len(argv) > 0 && strings.HasPrefix(argv[0], "chrome-extension://")
}

type nativeRequest struct {
	ID   json.RawMessage `json:"id"`
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args"`
}

type nativeReply struct {
	ID     json.RawMessage `json:"id,omitempty"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Code   string          `json:"code,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// NativeHost serves the browser on in and out until in ends (the browser
// closes it when the extension disconnects). argv is hyroutectl's
// arguments; app is the browser's exe ("" = unknown), put into each
// request's args. It returns the exit code.
func NativeHost(ctx context.Context, argv []string, in io.Reader, out io.Writer, app string, d *Deps) int {
	if !slices.Contains(ctl.BrowserOrigins, argv[0]) {
		writeNative(out, nativeReply{Code: ctl.CodeDenied, Error: "Это расширение не может управлять HyRoute"})
		return ctl.ExitCode(ctl.CodeDenied)
	}
	dd := *d
	dd.Stdout, dd.Stderr = io.Discard, io.Discard
	for {
		body, err := readNative(in)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0
			}
			writeNative(out, nativeReply{Code: ctl.CodeUsage, Error: "Неверное сообщение от браузера"})
			return ctl.ExitCode(ctl.CodeUsage)
		}
		rep := nativeOne(ctx, body, app, &dd)
		if err := writeNative(out, rep); err != nil {
			return 1
		}
	}
}

// nativeOne answers one message.
func nativeOne(ctx context.Context, body []byte, app string, d *Deps) nativeReply {
	var req nativeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nativeReply{Code: ctl.CodeUsage, Error: "Неверное сообщение от браузера"}
	}
	rep := nativeReply{ID: req.ID}
	if !slices.Contains(ctl.BrowserCommands, req.Cmd) {
		rep.Code, rep.Error = ctl.CodeUnknown, fmt.Sprintf("Команда «%s» недоступна расширению", req.Cmd)
		return rep
	}
	args := map[string]json.RawMessage{}
	if len(req.Args) > 0 && string(req.Args) != "null" {
		if err := json.Unmarshal(req.Args, &args); err != nil {
			rep.Code, rep.Error = ctl.CodeUsage, "Неверные параметры команды"
			return rep
		}
	}
	// The browser's program, as the host sees it: the extension cannot
	// know it, nor claim another.
	delete(args, "app")
	if app != "" {
		args["app"], _ = json.Marshal(app)
	}
	c := &client{d: d, inv: &Invocation{Name: req.Cmd, Wire: req.Cmd, Args: args, JSON: true, Timeout: nativeTimeout}}
	res, f := c.exchange(ctx, func(json.RawMessage) error { return nil })
	if f != nil {
		rep.Code, rep.Error = f.code, f.msg
		switch f.code {
		case ctl.CodeNotRunning:
			rep.Error = "HyRoute не запущен"
		case ctl.CodeOff:
			// No pipe, or one for neither: the extension is off as well
			// (the pipe runs while it is on).
			rep.Code, rep.Error = ctl.CodeBrowserOff, msgBrowserOff
		}
		return rep
	}
	rep.OK, rep.Result = true, res
	return rep
}

func readNative(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err // io.EOF: the browser closed the pipe
	}
	if n == 0 || n > maxNativeIn {
		return nil, fmt.Errorf("native message of %d bytes", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}

func writeNative(w io.Writer, rep nativeReply) error {
	b, err := ctl.Marshal(rep)
	if err != nil {
		return err
	}
	if len(b) > maxNativeOut {
		b, _ = ctl.Marshal(nativeReply{ID: rep.ID, Code: ctl.CodeTooBig, Error: "Ответ HyRoute слишком большой для браузера"})
	}
	buf := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err = w.Write(buf)
	return err
}
