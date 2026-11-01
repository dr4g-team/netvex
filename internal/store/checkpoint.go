package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/drag-team/netvex/internal/model"
)

// CheckpointEntry is what a resumed run needs to know about a finished proxy.
type CheckpointEntry struct {
	Status   model.Status
	Protocol model.Protocol
}

type Checkpoint struct {
	file      *os.File
	writer    *bufio.Writer
	syncEvery int
	pending   int
}

func OpenCheckpoint(path string, resume, force bool, syncEvery int, maxResults int) (*Checkpoint, map[string]CheckpointEntry, error) {
	if syncEvery < 1 || syncEvery > 100_000 {
		return nil, nil, errors.New("checkpoint sync interval is outside safe bounds")
	}
	completed := make(map[string]CheckpointEntry)
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, nil, errors.New("checkpoint must be a regular file, not a symbolic link")
		}
		if !checkpointPrivate(info) {
			return nil, nil, errors.New("checkpoint must not be readable by group or other users")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("inspect checkpoint: %w", statErr)
	} else if resume {
		return nil, nil, errors.New("resume checkpoint does not exist")
	}
	flags := os.O_CREATE | os.O_WRONLY
	if resume {
		// Not O_APPEND: on Windows that opens the handle without the write access
		// truncation needs, and the exclusive lock already makes this the only writer.
		flags = os.O_RDWR
	} else if !force {
		flags |= os.O_EXCL
	}
	file, err := openNoFollow(path, flags, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("open checkpoint: %w", err)
	}
	if err := lockCheckpoint(file); err != nil {
		_ = file.Close()
		if errors.Is(err, errCheckpointLocked) {
			return nil, nil, errors.New("checkpoint is already open by another process")
		}
		return nil, nil, fmt.Errorf("lock checkpoint: %w", err)
	}
	if info, statErr := file.Stat(); statErr != nil {
		_ = file.Close()
		return nil, nil, statErr
	} else if !checkpointPrivate(info) {
		_ = file.Close()
		return nil, nil, errors.New("checkpoint must not be readable by group or other users")
	}
	if force && !resume {
		if err := file.Truncate(0); err != nil {
			_ = file.Close()
			return nil, nil, fmt.Errorf("truncate checkpoint: %w", err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			return nil, nil, fmt.Errorf("seek checkpoint: %w", err)
		}
	}
	if resume {
		if err := truncatePartialFile(file); err != nil {
			_ = file.Close()
			return nil, nil, fmt.Errorf("repair checkpoint: %w", err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			return nil, nil, fmt.Errorf("seek checkpoint: %w", err)
		}
		var loadErr error
		completed, loadErr = scanCheckpointIDs(file, maxResults)
		if loadErr != nil {
			_ = file.Close()
			return nil, nil, loadErr
		}
		if _, err := file.Seek(0, io.SeekEnd); err != nil {
			_ = file.Close()
			return nil, nil, fmt.Errorf("seek checkpoint end: %w", err)
		}
	}
	return &Checkpoint{file: file, writer: bufio.NewWriterSize(file, 128<<10), syncEvery: syncEvery}, completed, nil
}

type modelResult struct {
	ID       string         `json:"id"`
	Status   model.Status   `json:"status"`
	Protocol model.Protocol `json:"protocol"`
}

func readCheckpointIDs(path string, maxResults int) (map[string]CheckpointEntry, error) {
	file, err := openNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return scanCheckpointIDs(file, maxResults)
}

func scanCheckpointIDs(reader io.Reader, maxResults int) (map[string]CheckpointEntry, error) {
	completed := make(map[string]CheckpointEntry)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), MaxResultBytes)
	count := 0
	for scanner.Scan() {
		count++
		if count > maxResults {
			return nil, errors.New("checkpoint result limit exceeded")
		}
		var result modelResult
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			return nil, fmt.Errorf("decode checkpoint line %d: %w", count, err)
		}
		if result.ID == "" || len(result.ID) > 128 || strings.IndexFunc(result.ID, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("checkpoint line %d has an invalid result ID", count)
		}
		// An interrupted record has no verdict, so the proxy stays pending.
		if result.Status != model.StatusInterrupted {
			completed[result.ID] = CheckpointEntry{Status: result.Status, Protocol: result.Protocol}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return completed, nil
}

// Replay emits every finished result. It reads through the handle holding the
// exclusive lock because Windows locks are mandatory: a second handle would fail
// with a lock violation, which broke resume on that platform.
func (c *Checkpoint) Replay(emit func(model.Result) error) error {
	if err := c.Sync(); err != nil {
		return err
	}
	if _, err := c.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek checkpoint: %w", err)
	}
	if err := decodeResults(c.file, func(result model.Result) error {
		if result.Status == model.StatusInterrupted {
			return nil
		}
		return emit(result)
	}); err != nil {
		return err
	}
	if _, err := c.file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek checkpoint end: %w", err)
	}
	return nil
}

func (c *Checkpoint) Write(result model.Result) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if len(data) > MaxResultBytes {
		return fmt.Errorf("serialized checkpoint result exceeds %d bytes", MaxResultBytes)
	}
	if _, err := c.writer.Write(data); err != nil {
		return err
	}
	if err := c.writer.WriteByte('\n'); err != nil {
		return err
	}
	c.pending++
	if c.pending >= c.syncEvery {
		return c.Sync()
	}
	return nil
}

func (c *Checkpoint) Sync() error {
	if err := c.writer.Flush(); err != nil {
		return err
	}
	if err := c.file.Sync(); err != nil {
		return err
	}
	c.pending = 0
	return nil
}

func (c *Checkpoint) Close() error {
	if c == nil || c.file == nil {
		return nil
	}
	err := c.Sync()
	closeErr := c.file.Close()
	c.file = nil
	if err != nil {
		return err
	}
	return closeErr
}

func truncatePartialFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return nil
	}
	var last [1]byte
	if _, err := file.ReadAt(last[:], info.Size()-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	const blockSize = 4096
	for end := info.Size(); end > 0; {
		start := end - blockSize
		if start < 0 {
			start = 0
		}
		block := make([]byte, end-start)
		if _, err := file.ReadAt(block, start); err != nil && err != io.EOF {
			return err
		}
		for index := len(block) - 1; index >= 0; index-- {
			if block[index] == '\n' {
				return file.Truncate(start + int64(index) + 1)
			}
		}
		end = start
	}
	return file.Truncate(0)
}

var errCheckpointLocked = errors.New("checkpoint locked")
