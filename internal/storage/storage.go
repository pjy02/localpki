package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store persists certificate metadata to a JSONL file.
type Store struct {
	path string
	mu   sync.Mutex
}

// Open prepares a store at the given path. The parent directory is created automatically.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	f.Close()
	return &Store{path: path}, nil
}

// InsertCertificate appends a certificate record in JSON lines format.
func (s *Store) InsertCertificate(ctx context.Context, cert CertificateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer f.Close()

	payload := struct {
		CertificateRecord
		Timestamp time.Time `json:"timestamp"`
	}{cert, time.Now().UTC()}
	if err := json.NewEncoder(f).Encode(payload); err != nil {
		return fmt.Errorf("encode record: %w", err)
	}
	return nil
}

// CertificateRecord is a summary stored in the persistent log.
type CertificateRecord struct {
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	SAN       string    `json:"san"`
	Profile   string    `json:"profile"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	PEM       string    `json:"pem"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

// Close is a no-op kept for API symmetry.
func (s *Store) Close() error {
	return nil
}
