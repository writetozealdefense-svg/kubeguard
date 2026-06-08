package history

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// fileStore is an append-only JSONL history backend.
type fileStore struct{ path string }

// OpenFile returns a JSONL-backed Store at path.
func OpenFile(path string) (Store, error) { return &fileStore{path: path}, nil }

func (s *fileStore) Append(r Record) error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open history %q: %w", s.path, err)
	}
	defer func() { _ = f.Close() }()
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("append history: %w", err)
	}
	return nil
}

func (s *fileStore) All() ([]Record, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read history %q: %w", s.path, err)
	}
	var out []Record
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("parse history line: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *fileStore) Close() error { return nil }
