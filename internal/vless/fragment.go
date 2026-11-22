package vless

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// TCPFragment is the supported Xray finalmask for TCP transports.
type TCPFragment struct {
	Packets  string `json:"packets"`
	Length   string `json:"length"`
	Interval string `json:"interval"`
}

var fragmentRange = regexp.MustCompile(`^[0-9]{1,4}(-[0-9]{1,4})?$`)

func (f TCPFragment) Validate() error {
	if f == (TCPFragment{}) {
		return nil
	}
	if (f.Packets != "tlshello" && !fragmentRange.MatchString(f.Packets)) ||
		!fragmentRange.MatchString(f.Length) || !fragmentRange.MatchString(f.Interval) {
		return errors.New("недопустимые параметры TCP fragment")
	}
	first, last, rangeSet := strings.Cut(f.Length, "-")
	from, _ := strconv.Atoi(first)
	to, _ := strconv.Atoi(last)
	if from == 0 || rangeSet && to == 0 {
		return errors.New("длина TCP fragment должна быть больше нуля")
	}
	return nil
}

type tcpMask struct {
	Type     string      `json:"type"`
	Settings TCPFragment `json:"settings"`
}

func (f TCPFragment) finalMask() map[string][]tcpMask {
	return map[string][]tcpMask{"tcp": {{Type: "fragment", Settings: f}}}
}

// ParseTCPFragment reads the finalmask shape shared by Xray JSON and the
// VLESS fm parameter. Never pass unknown fields or mask types to Xray.
func ParseTCPFragment(raw []byte) (TCPFragment, error) {
	var mask map[string]json.RawMessage
	if err := json.Unmarshal(raw, &mask); err == nil {
		if len(mask) == 0 {
			return TCPFragment{}, nil
		}
		if len(mask) == 1 {
			var entries []tcpMask
			dec := json.NewDecoder(bytes.NewReader(mask["tcp"]))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&entries); err == nil && len(entries) == 1 &&
				entries[0].Type == "fragment" && entries[0].Settings != (TCPFragment{}) {
				f := entries[0].Settings
				return f, f.Validate()
			}
		}
	}
	return TCPFragment{}, errors.New("поддерживается только TCP fragment")
}
