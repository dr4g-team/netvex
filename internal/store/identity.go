package store

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const identityKeyBytes = 32

// LoadIdentityKey returns the local secret that scopes credentialed result IDs,
// creating it on first use. IDs stay comparable across runs on this data
// directory, while IDs copied elsewhere reveal nothing about the credentials.
func LoadIdentityKey(dataDir string) ([]byte, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	path := filepath.Join(dataDir, "identity.key")
	if key, err := readIdentityKey(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	key := EphemeralIdentityKey()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return readIdentityKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create identity key: %w", err)
	}
	_, err = file.Write(key)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("write identity key: %w", err)
	}
	return key, nil
}

func readIdentityKey(path string) ([]byte, error) {
	file, err := openNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !checkpointPrivate(info) {
		return nil, errors.New("identity key must not be readable by group or other users")
	}
	key := make([]byte, identityKeyBytes)
	if _, err := io.ReadFull(file, key); err != nil {
		return nil, fmt.Errorf("read identity key: %w", err)
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return nil, errors.New("identity key must contain exactly 32 bytes")
	}
	return key, nil
}

// EphemeralIdentityKey returns a random key valid for this process only.
func EphemeralIdentityKey() []byte {
	key := make([]byte, identityKeyBytes)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}
