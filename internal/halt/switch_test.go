package halt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInterpret(t *testing.T) {
	cases := []struct {
		in      string
		err     error
		halted  bool
		wantWhy string
	}{
		{"running\n", nil, false, "running"},
		{"  RUN  ", nil, false, "running"},
		{"0", nil, false, "running"},
		{"halted", nil, true, "halted"},
		{"halt", nil, true, "halted"},
		{"1\n", nil, true, "halted"},
		{"", nil, true, "corrupt"},
		{"maybe", nil, true, "corrupt"},
		{"", os.ErrNotExist, true, "cannot be read"},
		{"", errCorrupt, true, "corrupt"},
	}
	for _, tc := range cases {
		halted, why := interpret(tc.in, tc.err)
		if halted != tc.halted || !strings.Contains(why, tc.wantWhy) {
			t.Errorf("interpret(%q, %v) = %v %q", tc.in, tc.err, halted, why)
		}
	}
}

func TestReadFailClosedAndTransitions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "halt")
	s := New(path)

	halted, trans, why := s.Read()
	if !halted || trans != "halt" || !strings.Contains(why, "cannot be read") {
		t.Fatalf("missing file: halted=%v trans=%q why=%q", halted, trans, why)
	}
	halted, trans, _ = s.Read()
	if !halted || trans != "" {
		t.Fatalf("second missing read should not repeat the transition: %v %q", halted, trans)
	}

	if err := os.WriteFile(path, []byte("running\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	halted, trans, why = s.Read()
	if halted || trans != "resume" || !strings.Contains(why, "running") {
		t.Fatalf("resume: halted=%v trans=%q why=%q", halted, trans, why)
	}

	if err := os.WriteFile(path, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	halted, trans, why = s.Read()
	if !halted || trans != "halt" || !strings.Contains(why, "corrupt") {
		t.Fatalf("corrupt: halted=%v trans=%q why=%q", halted, trans, why)
	}

	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	link := New(path + ".link")
	halted, trans, why = link.Read()
	if !halted || trans != "halt" || !strings.Contains(why, "corrupt") {
		t.Fatalf("symlink: halted=%v trans=%q why=%q", halted, trans, why)
	}
}
