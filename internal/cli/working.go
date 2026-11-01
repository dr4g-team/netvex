package cli

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/dr4g-team/netvex/internal/model"
)

var (
	workingProtocols    = []model.Protocol{model.ProtocolHTTP, model.ProtocolHTTPS, model.ProtocolSOCKS4, model.ProtocolSOCKS4A, model.ProtocolSOCKS5}
	templatePlaceholder = regexp.MustCompile(`\{[^{}]*\}`)
	templateFields      = map[string]struct{}{"{protocol}": {}, "{host}": {}, "{port}": {}, "{user}": {}, "{pass}": {}, "{hostport}": {}, "{uri}": {}}
	templateAliases     = map[string]string{"uri": "{uri}", "hostport": "{hostport}", "colon": "{host}:{port}:{user}:{pass}"}
)

func parseWorkingTemplate(value string) (string, error) {
	if value == "" {
		return "{uri}", nil
	}
	if alias, ok := templateAliases[value]; ok {
		return alias, nil
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", errors.New("working-template must be a single line")
	}
	placeholders := templatePlaceholder.FindAllString(value, -1)
	if len(placeholders) == 0 {
		return "", errors.New("working-template needs a placeholder such as {host} or an alias: uri, hostport, colon")
	}
	for _, placeholder := range placeholders {
		if _, ok := templateFields[placeholder]; !ok {
			return "", fmt.Errorf("working-template has unknown placeholder %s", placeholder)
		}
	}
	return value, nil
}

func renderWorking(template string, proxy model.Proxy) string {
	if template == "{uri}" {
		return proxy.FullURI()
	}
	user, pass := "", ""
	if proxy.Credentials != nil {
		user, pass = templateValue(proxy.Credentials.Username), templateValue(proxy.Credentials.Password)
	}
	return strings.NewReplacer(
		"{protocol}", string(proxy.Protocol), "{host}", proxy.Host, "{port}", strconv.Itoa(int(proxy.Port)),
		"{user}", user, "{pass}", pass, "{hostport}", proxy.Address(), "{uri}", proxy.FullURI(),
	).Replace(template)
}

// templateValue keeps decoded credentials from splitting an output record.
func templateValue(value string) string {
	if strings.ContainsAny(value, "\r\n") {
		return url.QueryEscape(value)
	}
	return value
}

// workingSink collects validated proxies into one file or one file per protocol.
// It is shared with the input goroutine because resumed proxies are exported as
// soon as they are read, so every method takes the lock.
type workingSink struct {
	mu       sync.Mutex
	template string
	force    bool
	single   *secureOutput
	dir      string
	files    map[model.Protocol]*secureOutput
	count    int
	closed   bool
}

func openWorkingFile(path, template string, force bool) (*workingSink, error) {
	file, err := openSecureOutput(path, force)
	if err != nil {
		return nil, err
	}
	return &workingSink{template: template, force: force, single: file}, nil
}

// openWorkingDir refuses existing files now, because discovering one when the
// first proxy of that protocol validates would abort a run already in progress.
func openWorkingDir(dir, template string, force bool) (*workingSink, error) {
	if !force {
		for _, path := range workingDirPaths(dir) {
			if _, err := os.Lstat(path); err == nil {
				return nil, os.ErrExist
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	}
	return &workingSink{template: template, force: force, dir: dir, files: make(map[model.Protocol]*secureOutput, len(workingProtocols))}, nil
}

func workingDirPaths(dir string) []string {
	paths := make([]string, len(workingProtocols))
	for index, protocol := range workingProtocols {
		paths[index] = filepath.Join(dir, string(protocol)+".txt")
	}
	return paths
}

func (s *workingSink) Write(proxy model.Proxy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("working output is closed")
	}
	file := s.single
	if file == nil {
		file = s.files[proxy.Protocol]
		if file == nil {
			opened, err := openSecureOutput(filepath.Join(s.dir, string(proxy.Protocol)+".txt"), s.force)
			if err != nil {
				return err
			}
			s.files[proxy.Protocol] = opened
			file = opened
		}
	}
	if err := file.WriteLine(renderWorking(s.template, proxy)); err != nil {
		return err
	}
	s.count++
	return nil
}

func (s *workingSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *workingSink) Commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.single != nil {
		return s.single.Commit()
	}
	for _, file := range s.files {
		if err := file.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *workingSink) Abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.single.Abort()
	for _, file := range s.files {
		file.Abort()
	}
}

func commitPartialWorking(output *workingSink, path string, diagnostics io.Writer) error {
	if output == nil || output.Count() < 1 {
		return nil
	}
	if err := output.Commit(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(diagnostics, "saved %d validated proxies from interrupted run to %q\n", output.Count(), path)
	return nil
}
