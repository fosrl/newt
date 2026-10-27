package nativessh

import (
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// maxLineRunes caps how much of a single interactive line is buffered.
const maxLineRunes = 4096

type escState int

const (
	escNone escState = iota
	escStart
	escCSI
	escSS3
)

// lineRecorder reconstructs the command lines a user types into an
// interactive shell from the raw bytes their SSH client sends. It follows
// the common line-editing keys (cursor movement, backspace, kill line/word)
// so edited lines come out right, and flags lines that used history recall
// or tab completion as inexact since their final text is only known to the
// shell.
//
// Input is not recorded while:
//   - the terminal is in canonical mode with echo off (password prompts from
//     sudo, passwd, ssh, ...), as reported by hidden, or
//   - a full-screen program has switched to the alternate screen (vim, less,
//     top, ...), detected by watching the PTY output passed to
//     observeOutput.
type lineRecorder struct {
	onLine func(line string, inexact bool)
	hidden func() bool

	mu      sync.Mutex
	line    []rune
	cursor  int
	inexact bool
	discard bool // the line contained hidden input
	esc     escState
	params  []byte
	utf8Buf []byte
	wasAlt  bool

	altScreen atomic.Bool

	// Output scanner state, only touched from the output goroutine.
	outState int
	outParam int
	outMatch bool
}

func newLineRecorder(onLine func(line string, inexact bool), hidden func() bool) *lineRecorder {
	return &lineRecorder{onLine: onLine, hidden: hidden}
}

type completedLine struct {
	text    string
	inexact bool
}

// Write consumes client input. It never fails so it can sit in an
// io.TeeReader without affecting the session.
func (r *lineRecorder) Write(p []byte) (int, error) {
	hidden := r.hidden != nil && r.hidden()
	alt := r.altScreen.Load()

	var lines []completedLine

	r.mu.Lock()
	if alt != r.wasAlt {
		// Entering or leaving a full-screen program: whatever was buffered
		// does not belong to a shell command line.
		r.reset()
		r.esc = escNone
		r.wasAlt = alt
	}
	if !alt {
		for _, b := range p {
			if l, ok := r.feed(b, hidden); ok {
				lines = append(lines, l)
			}
		}
	}
	r.mu.Unlock()

	for _, l := range lines {
		r.onLine(l.text, l.inexact)
	}
	return len(p), nil
}

func (r *lineRecorder) reset() {
	r.line = r.line[:0]
	r.cursor = 0
	r.inexact = false
	r.discard = false
	r.utf8Buf = r.utf8Buf[:0]
}

// feed processes one input byte and returns a completed line when the user
// pressed enter.
func (r *lineRecorder) feed(b byte, hidden bool) (completedLine, bool) {
	switch r.esc {
	case escStart:
		r.esc = escNone
		switch b {
		case '[':
			r.esc = escCSI
			r.params = r.params[:0]
		case 'O':
			r.esc = escSS3
		case 'b', 'B':
			r.wordLeft()
		case 'f', 'F':
			r.wordRight()
		case 0x7f, 0x08:
			r.killWordBack()
		case 0x1b:
			r.esc = escStart
		}
		return completedLine{}, false
	case escCSI:
		if b >= 0x40 && b <= 0x7e {
			r.esc = escNone
			r.handleCSI(string(r.params), b)
		} else if len(r.params) < 16 {
			r.params = append(r.params, b)
		}
		return completedLine{}, false
	case escSS3:
		r.esc = escNone
		r.handleCSI("", b)
		return completedLine{}, false
	}

	switch b {
	case '\r', '\n':
		l := completedLine{text: strings.TrimSpace(string(r.line)), inexact: r.inexact}
		keep := !r.discard && (l.text != "" || l.inexact)
		r.reset()
		return l, keep
	case 0x1b:
		r.esc = escStart
	case 0x7f, 0x08: // backspace
		if r.cursor > 0 {
			r.line = append(r.line[:r.cursor-1], r.line[r.cursor:]...)
			r.cursor--
		}
	case 0x03: // ctrl-c abandons the line
		r.reset()
	case 0x15: // ctrl-u
		r.line = append(r.line[:0], r.line[r.cursor:]...)
		r.cursor = 0
	case 0x0b: // ctrl-k
		r.line = r.line[:r.cursor]
	case 0x17: // ctrl-w
		r.killWordBack()
	case 0x01: // ctrl-a
		r.cursor = 0
	case 0x05: // ctrl-e
		r.cursor = len(r.line)
	case 0x02: // ctrl-b
		r.moveLeft()
	case 0x06: // ctrl-f
		r.moveRight()
	case 0x04: // ctrl-d deletes under the cursor
		r.deleteAtCursor()
	case 0x09, 0x10, 0x0e, 0x12: // tab, ctrl-p, ctrl-n, ctrl-r
		r.inexact = true
	default:
		if b < 0x20 {
			return completedLine{}, false
		}
		if hidden {
			r.discard = true
			return completedLine{}, false
		}
		r.insertByte(b)
	}
	return completedLine{}, false
}

func (r *lineRecorder) handleCSI(params string, final byte) {
	switch final {
	case 'D':
		r.moveLeft()
	case 'C':
		r.moveRight()
	case 'H':
		r.cursor = 0
	case 'F':
		r.cursor = len(r.line)
	case 'A', 'B': // history up/down
		r.inexact = true
	case '~':
		switch params {
		case "1", "7":
			r.cursor = 0
		case "4", "8":
			r.cursor = len(r.line)
		case "3":
			r.deleteAtCursor()
		}
		// 200~/201~ bracket pasted text, which is fed through as normal
		// input, so the markers themselves are ignored.
	}
}

func (r *lineRecorder) insertByte(b byte) {
	r.utf8Buf = append(r.utf8Buf, b)
	if !utf8.FullRune(r.utf8Buf) {
		if len(r.utf8Buf) >= utf8.UTFMax {
			r.utf8Buf = r.utf8Buf[:0]
		}
		return
	}
	ch, _ := utf8.DecodeRune(r.utf8Buf)
	r.utf8Buf = r.utf8Buf[:0]
	if len(r.line) >= maxLineRunes {
		r.inexact = true
		return
	}
	r.line = append(r.line, 0)
	copy(r.line[r.cursor+1:], r.line[r.cursor:])
	r.line[r.cursor] = ch
	r.cursor++
}

func (r *lineRecorder) moveLeft() {
	if r.cursor > 0 {
		r.cursor--
	}
}

func (r *lineRecorder) moveRight() {
	if r.cursor < len(r.line) {
		r.cursor++
	}
}

func (r *lineRecorder) deleteAtCursor() {
	if r.cursor < len(r.line) {
		r.line = append(r.line[:r.cursor], r.line[r.cursor+1:]...)
	}
}

func (r *lineRecorder) wordLeft() {
	for r.cursor > 0 && r.line[r.cursor-1] == ' ' {
		r.cursor--
	}
	for r.cursor > 0 && r.line[r.cursor-1] != ' ' {
		r.cursor--
	}
}

func (r *lineRecorder) wordRight() {
	for r.cursor < len(r.line) && r.line[r.cursor] == ' ' {
		r.cursor++
	}
	for r.cursor < len(r.line) && r.line[r.cursor] != ' ' {
		r.cursor++
	}
}

func (r *lineRecorder) killWordBack() {
	end := r.cursor
	r.wordLeft()
	r.line = append(r.line[:r.cursor], r.line[end:]...)
}

// observeOutput scans PTY output for DEC private mode sequences that switch
// to and from the alternate screen (ESC [ ? 1049/1047/47 h|l).
func (r *lineRecorder) observeOutput(p []byte) {
	for _, b := range p {
		switch r.outState {
		case 0:
			if b == 0x1b {
				r.outState = 1
			}
		case 1:
			switch b {
			case '[':
				r.outState = 2
			case 0x1b:
			default:
				r.outState = 0
			}
		case 2:
			if b == '?' {
				r.outState = 3
				r.outParam = 0
				r.outMatch = false
			} else {
				r.outState = 0
			}
		case 3:
			switch {
			case b >= '0' && b <= '9':
				if r.outParam < 100000 {
					r.outParam = r.outParam*10 + int(b-'0')
				}
			case b == ';':
				r.outMatch = r.outMatch || isAltScreenMode(r.outParam)
				r.outParam = 0
			case b == 'h' || b == 'l':
				if r.outMatch || isAltScreenMode(r.outParam) {
					r.altScreen.Store(b == 'h')
				}
				r.outState = 0
			default:
				r.outState = 0
			}
		}
	}
}

func isAltScreenMode(mode int) bool {
	return mode == 1049 || mode == 1047 || mode == 47
}

// outputObserver adapts a lineRecorder to io.Writer for PTY output.
type outputObserver struct{ r *lineRecorder }

func (o outputObserver) Write(p []byte) (int, error) {
	o.r.observeOutput(p)
	return len(p), nil
}
