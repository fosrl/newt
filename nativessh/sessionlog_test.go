package nativessh

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

type recordedLine struct {
	text    string
	inexact bool
}

func recordLines(t *testing.T, hidden func() bool, chunks ...string) []recordedLine {
	t.Helper()
	var got []recordedLine
	r := newLineRecorder(func(line string, inexact bool) {
		got = append(got, recordedLine{line, inexact})
	}, hidden)
	for _, c := range chunks {
		_, _ = r.Write([]byte(c))
	}
	return got
}

func TestLineRecorderEditing(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   []recordedLine
	}{
		{"simple", []string{"ls -la\r"}, []recordedLine{{"ls -la", false}}},
		{"split chunks", []string{"ec", "ho hi", "\r"}, []recordedLine{{"echo hi", false}}},
		{"multiple lines", []string{"pwd\rwhoami\r"}, []recordedLine{{"pwd", false}, {"whoami", false}}},
		{"backspace", []string{"lss\x7f -l\r"}, []recordedLine{{"ls -l", false}}},
		{"cursor insert", []string{"ech hi\x1b[D\x1b[D\x1b[Do\r"}, []recordedLine{{"echo hi", false}}},
		{"ss3 arrows", []string{"ab\x1bODc\r"}, []recordedLine{{"acb", false}}},
		{"ctrl-a insert", []string{"ls\x01sudo \r"}, []recordedLine{{"sudo ls", false}}},
		{"ctrl-u", []string{"rm -rf /\x15ls\r"}, []recordedLine{{"ls", false}}},
		{"ctrl-w", []string{"git push origin\x17main\r"}, []recordedLine{{"git push main", false}}},
		{"ctrl-k", []string{"ls -la\x01\x06\x06\x0b\r"}, []recordedLine{{"ls", false}}},
		{"ctrl-c abandons", []string{"oops\x03ls\r"}, []recordedLine{{"ls", false}}},
		{"delete key", []string{"lsx\x1b[D\x1b[3~\r"}, []recordedLine{{"ls", false}}},
		{"empty lines skipped", []string{"\r\r  \r"}, nil},
		{"tab is inexact", []string{"cd /us\t\r"}, []recordedLine{{"cd /us", true}}},
		{"history recall", []string{"\x1b[A\r"}, []recordedLine{{"", true}}},
		{"utf8 split", []string{"echo \xc3", "\xa9\r"}, []recordedLine{{"echo é", false}}},
		{"bracketed paste", []string{"\x1b[200~echo pasted\x1b[201~\r"}, []recordedLine{{"echo pasted", false}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := recordLines(t, nil, tt.chunks...)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d lines %+v, want %+v", len(got), got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("line %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLineRecorderSkipsHiddenInput(t *testing.T) {
	hidden := false
	var got []string
	r := newLineRecorder(func(line string, _ bool) { got = append(got, line) }, func() bool { return hidden })

	_, _ = r.Write([]byte("sudo id\r"))
	hidden = true
	_, _ = r.Write([]byte("hunter2\r"))
	hidden = false
	_, _ = r.Write([]byte("exit\r"))

	want := []string{"sudo id", "exit"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLineRecorderSkipsAlternateScreen(t *testing.T) {
	var got []string
	r := newLineRecorder(func(line string, _ bool) { got = append(got, line) }, nil)
	out := outputObserver{r}

	_, _ = r.Write([]byte("vim notes.txt\r"))
	// Sequence split across output chunks.
	_, _ = out.Write([]byte("\x1b[?10"))
	_, _ = out.Write([]byte("49h"))
	_, _ = r.Write([]byte("ihello\x1b:wq\r"))
	_, _ = out.Write([]byte("\x1b[?1049l"))
	_, _ = r.Write([]byte("cat notes.txt\r"))

	want := []string{"vim notes.txt", "cat notes.txt"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func decodeBatch(t *testing.T, data string) []SessionRecord {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var records []SessionRecord
	if err := json.Unmarshal(jsonData, &records); err != nil {
		t.Fatal(err)
	}
	return records
}

func TestSessionLoggerFlushAndRetry(t *testing.T) {
	var batches [][]SessionRecord
	fail := true
	l := NewSessionLogger(func(data string) error {
		if fail {
			return errors.New("offline")
		}
		batches = append(batches, decodeBatch(t, data))
		return nil
	})
	defer l.Close()

	s := l.StartSession(SessionInfo{Username: "alice", SourceAddr: "100.90.128.2:5000", Transport: TransportSSH, Auth: AuthResult{Method: AuthMethodCertificate}})
	s.RecordCommand(ChannelShell, "ls", false)
	l.flush() // fails, retried later

	fail = false
	s.RecordCommand(ChannelShell, "pwd", false)
	l.flush()

	if len(batches) != 1 {
		t.Fatalf("got %d batches, want 1", len(batches))
	}
	var cmds []string
	for _, rec := range batches[0] {
		if rec.SessionID == "" || rec.Username != "alice" {
			t.Fatalf("bad record %+v", rec)
		}
		for _, c := range rec.Commands {
			cmds = append(cmds, c.Command)
		}
	}
	if strings.Join(cmds, ",") != "ls,pwd" {
		t.Fatalf("commands = %q, want ls,pwd", cmds)
	}

	// Nothing new: no batch is sent.
	l.flush()
	if len(batches) != 1 {
		t.Fatalf("idle flush sent a batch")
	}

	s.End()
	l.flush()
	if len(batches) != 2 || batches[1][0].EndedAt == nil {
		t.Fatalf("ended session not reported: %+v", batches)
	}
	if len(l.sessions) != 0 {
		t.Fatalf("ended session still tracked")
	}
}

func TestSessionLoggerCloseEndsActiveSessions(t *testing.T) {
	var records []SessionRecord
	l := NewSessionLogger(func(data string) error {
		records = append(records, decodeBatch(t, data)...)
		return nil
	})
	s := l.StartSession(SessionInfo{Username: "bob"})
	s.RecordCommand(ChannelExec, "uptime", false)
	l.Close()

	if len(records) != 1 || records[0].EndedAt == nil || len(records[0].Commands) != 1 {
		t.Fatalf("unexpected records after close: %+v", records)
	}

	// Recording after close is a no-op.
	s.RecordCommand(ChannelExec, "late", false)
	if l.StartSession(SessionInfo{}) != nil {
		t.Fatal("StartSession after Close should return nil")
	}
}

func TestNilSessionIsSafe(t *testing.T) {
	var l *SessionLogger
	s := l.StartSession(SessionInfo{})
	s.RecordCommand(ChannelShell, "ls", false)
	s.End()
	l.Close()
}

func TestTruncateCommand(t *testing.T) {
	long := strings.Repeat("é", maxCommandBytes)
	got := truncateCommand(long)
	if len(got) > maxCommandBytes || !strings.HasPrefix(long, got) {
		t.Fatalf("bad truncation: len=%d", len(got))
	}
}
