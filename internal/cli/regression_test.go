package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/store"
)

// connectProxy is a loopback CONNECT proxy fixture that serves until the test ends.
func connectProxy(t *testing.T) string {
	t.Helper()
	return proxyFixture(t, func(client net.Conn, reader *bufio.Reader, request *http.Request) {
		upstream, err := net.Dial("tcp", request.Host)
		if err != nil {
			return
		}
		defer upstream.Close()
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(upstream, reader) }()
		_, _ = io.Copy(client, upstream)
	})
}

func proxyFixture(t *testing.T, handle func(net.Conn, *bufio.Reader, *http.Request)) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local proxy socket unavailable: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer client.Close()
				reader := bufio.NewReader(client)
				request, readErr := http.ReadRequest(reader)
				if readErr == nil {
					handle(client, reader, request)
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func echoTarget(t *testing.T) string {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"origin":"8.8.8.8"}`)
	}))
	t.Cleanup(target.Close)
	return target.URL
}

func checkpointRecords(t *testing.T, path string) []model.Result {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []model.Result
	for _, line := range bytes.Split(bytes.TrimSpace(payload), []byte("\n")) {
		var record model.Result
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

func TestFlagsMayFollowPositionalArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(path, []byte("proxy.test:8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, diag := run([]string{"import", path, "--format", "jsonl", "--protocol", "socks5"}, "")
	if code != ExitOK || !strings.Contains(out, `"protocol":"socks5"`) {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	if code, _, diag := run([]string{"import", "--format", "jsonl", "--", "--not-a-flag"}, ""); code != ExitOperational || !strings.Contains(diag, "--not-a-flag") {
		t.Fatalf("terminator ignored: code=%d diag=%q", code, diag)
	}
	if code, _, _ := run([]string{"import", path, "--unknown"}, ""); code != ExitUsage {
		t.Fatalf("unknown trailing flag code=%d", code)
	}
}

func TestResumeValidatesEveryAccountOnOneGateway(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "proxies.txt")
	lines := fmt.Sprintf("http://alpha:1@%[1]s\nhttp://bravo:2@%[1]s\nhttp://charlie:3@%[1]s\n", proxy)
	if err := os.WriteFile(input, []byte(lines), 0600); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(dir, "run.jsonl")
	base := []string{"check", "--quiet", "--repeat", "1", "--allow-private-targets", "--allow-private-proxies", "--target", target}
	if code, _, diag := run(append(append([]string{}, base...), "--checkpoint", checkpoint, input), ""); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	records := checkpointRecords(t, checkpoint)
	seen := map[string]bool{}
	for _, record := range records {
		seen[record.ID] = true
	}
	if len(records) != 3 || len(seen) != 3 {
		t.Fatalf("records=%d distinct=%d", len(records), len(seen))
	}
	payload, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("alpha")) {
		t.Fatal("credential leaked into checkpoint")
	}
	first := payload[:bytes.IndexByte(payload, '\n')+1]
	if err := os.WriteFile(checkpoint, first, 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, diag := run(append(append([]string{}, base...), "--resume", checkpoint, input), ""); code != ExitOK {
		t.Fatalf("resume code=%d diag=%q", code, diag)
	}
	if resumed := checkpointRecords(t, checkpoint); len(resumed) != 3 {
		t.Fatalf("resume validated %d of 3 accounts", len(resumed))
	}
}

func TestResumeRetriesInterruptedProxies(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	checkpoint := filepath.Join(t.TempDir(), "run.jsonl")
	parsed := model.Proxy{Protocol: model.ProtocolHTTP, Host: "127.0.0.1"}
	_, portText, _ := net.SplitHostPort(proxy)
	fmt.Sscanf(portText, "%d", &parsed.Port)
	record, err := json.Marshal(model.Result{ID: parsed.Key(), Endpoint: proxy, Status: model.StatusInterrupted, Attempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checkpoint, append(record, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"check", "--quiet", "--repeat", "1", "--allow-private-targets", "--allow-private-proxies", "--target", target, "--resume", checkpoint}
	if code, _, diag := run(args, proxy+"\n"); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	records := checkpointRecords(t, checkpoint)
	if len(records) != 2 || records[1].Status != model.StatusOK {
		t.Fatalf("records=%+v", records)
	}
}

func TestHostileAuthChallengeCannotAbortSavedRun(t *testing.T) {
	hostile := proxyFixture(t, func(client net.Conn, _ *bufio.Reader, _ *http.Request) {
		fmt.Fprintf(client, "HTTP/1.1 407 Auth\r\nProxy-Authenticate: X%s realm=x\r\nContent-Length: 0\r\n\r\n", strings.Repeat("a", 8000))
	})
	proxy, target := connectProxy(t), echoTarget(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "proxies.txt")
	if err := os.WriteFile(input, []byte("http://user:secret@"+hostile+"\n"+proxy+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"check", "--quiet", "--repeat", "1", "--save", "--data-dir", dir, "--allow-private-targets", "--allow-private-proxies", "--target", target, input}
	if code, _, diag := run(args, ""); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	path, err := store.ResolveRun(dir, "latest")
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[model.Status]int{}
	if err := store.ReadResults(path, func(result model.Result) error {
		statuses[result.Status]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if statuses[model.StatusOK] != 1 || statuses[model.StatusAuthFailed] != 1 {
		t.Fatalf("statuses=%v", statuses)
	}
}

// blockedStdin yields its payload once and then blocks like an idle pipe.
type blockedStdin struct {
	payload []byte
	release chan struct{}
}

func (b *blockedStdin) Read(data []byte) (int, error) {
	if len(b.payload) > 0 {
		n := copy(data, b.payload)
		b.payload = b.payload[n:]
		return n, nil
	}
	<-b.release
	return 0, io.EOF
}

func TestInterruptEndsRunWhileStandardInputStaysOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("self-delivered interrupts are not available on Windows")
	}
	hanging := proxyFixture(t, func(client net.Conn, _ *bufio.Reader, _ *http.Request) {
		_, _ = io.Copy(io.Discard, client)
	})
	checkpoint := filepath.Join(t.TempDir(), "run.jsonl")
	stdin := &blockedStdin{payload: []byte(strings.Repeat(hanging+"\n", 1) + "\n"), release: make(chan struct{})}
	t.Cleanup(func() { close(stdin.release) })
	var out, diag bytes.Buffer
	cli := CLI{Stdout: &out, Stderr: &diag, Stdin: stdin}
	done := make(chan int, 1)
	go func() {
		done <- cli.Run([]string{"check", "--quiet", "--repeat", "1", "--input-format", "text", "--checkpoint", checkpoint, "--allow-private-targets", "--allow-private-proxies", "--target", "http://127.0.0.1:9/"})
	}()
	time.Sleep(200 * time.Millisecond)
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != ExitInterrupted {
			t.Fatalf("code=%d diag=%q", code, diag.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop while standard input stayed open")
	}
	if payload, err := os.ReadFile(checkpoint); err != nil || bytes.Contains(payload, []byte(`"interrupted"`)) {
		t.Fatalf("checkpoint=%q err=%v", payload, err)
	}
}

func TestPrescreenRejectsDeadGatewaysAndValidatesTheRest(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	dead := listener.Addr().String()
	_ = listener.Close()
	code, out, diag := run([]string{"check", "--prescreen", "--prescreen-retries", "0", "--repeat", "1", "--format", "jsonl", "--allow-private-targets", "--allow-private-proxies", "--target", target}, proxy+"\n"+dead+"\n")
	if code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	statuses := map[string]model.Status{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var result model.Result
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.Fatal(err)
		}
		statuses[result.Endpoint] = result.Status
	}
	if statuses[proxy] != model.StatusOK || statuses[dead] != model.StatusFailed || len(statuses) != 2 {
		t.Fatalf("statuses=%v", statuses)
	}
}

func TestPrescreenFlagBounds(t *testing.T) {
	for _, args := range [][]string{{"--prescreen-concurrency", "70000"}, {"--prescreen-retries", "9"}, {"--prescreen-timeout", "1ms"}} {
		if code, _, _ := run(append([]string{"check"}, args...), "proxy.test:80\n"); code != ExitUsage {
			t.Fatalf("%v code=%d", args, code)
		}
	}
	if workers := boundedPrescreenWorkers(1<<40, 128); workers < 1 {
		t.Fatalf("workers=%d", workers)
	}
}
