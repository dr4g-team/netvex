package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dr4g-team/netvex/internal/fsx"
)

type secureOutput struct {
	f      *os.File
	w      *bufio.Writer
	temp   string
	final  string
	force  bool
	closed bool
}

func openSecureOutput(path string, force bool) (*secureOutput, error) {
	if !force {
		if _, err := os.Lstat(path); err == nil {
			return nil, os.ErrExist
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, err
	}
	return &secureOutput{f: f, w: bufio.NewWriterSize(f, 64<<10), temp: f.Name(), final: path, force: force}, nil
}

func (s *secureOutput) WriteLine(value string) error {
	if s == nil || s.closed {
		return errors.New("output is closed")
	}
	if strings.ContainsAny(value, "\r\n") {
		return errors.New("unsafe proxy value")
	}
	_, err := fmt.Fprintln(s.w, value)
	return err
}

func (s *secureOutput) WriteJSON(value any) error {
	if s == nil || s.closed {
		return errors.New("output is closed")
	}
	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func (s *secureOutput) WriteBytes(value []byte) error {
	if s == nil || s.closed {
		return errors.New("output is closed")
	}
	_, err := s.w.Write(value)
	return err
}

func (s *secureOutput) Write(value []byte) (int, error) {
	if s == nil || s.closed {
		return 0, errors.New("output is closed")
	}
	return s.w.Write(value)
}

func (s *secureOutput) Commit() error {
	if s == nil || s.closed {
		return errors.New("output is already closed")
	}
	s.closed = true
	if err := s.w.Flush(); err != nil {
		_ = s.f.Close()
		_ = os.Remove(s.temp)
		return err
	}
	if err := s.f.Sync(); err != nil {
		_ = s.f.Close()
		_ = os.Remove(s.temp)
		return err
	}
	if err := s.f.Close(); err != nil {
		_ = os.Remove(s.temp)
		return err
	}
	if s.force {
		if err := fsx.Replace(s.temp, s.final); err != nil {
			_ = os.Remove(s.temp)
			return err
		}
	} else {
		if err := os.Link(s.temp, s.final); err != nil {
			_ = os.Remove(s.temp)
			return err
		}
		if err := os.Remove(s.temp); err != nil {
			return err
		}
	}
	return fsx.SyncParent(s.final)
}

func (s *secureOutput) Abort() {
	if s == nil || s.closed {
		return
	}
	s.closed = true
	_ = s.f.Close()
	_ = os.Remove(s.temp)
}

func samePath(a, b string) (bool, error) {
	aa, err := canonicalPath(a)
	if err != nil {
		return false, err
	}
	bb, err := canonicalPath(b)
	if err != nil {
		return false, err
	}
	return fsx.SameCanonicalPath(aa, bb), nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := abs
	missing := []string{}
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !errors.Is(resolveErr, os.ErrNotExist) {
			return "", resolveErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", resolveErr
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}
