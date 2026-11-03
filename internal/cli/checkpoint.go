package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/drag-team/netvex-go/internal/config"
	"github.com/drag-team/netvex-go/internal/model"
)

const checkpointConfigSuffix = ".config"

// checkpointFingerprint covers the settings that decide a verdict. Resuming with
// different rules would silently mix results that answer different questions;
// tuning such as concurrency or timeouts stays free to change between sessions.
func checkpointFingerprint(cfg config.Config, protocol model.Protocol) string {
	payload, err := json.Marshal(struct {
		Protocol                model.Protocol
		Targets                 []string
		TargetRules             map[string]config.ResponseRules
		RequireText, RejectText []string
		ExpectJSON              []string
		ExpectedBodySHA         string
		ExpectCountries         []string
		PinSHA256               []string
		Repeat, RotationSamples int
		TargetQuorum            int
		MinSuccessRate          float64
		MinResponseBytes        int64
		MinThroughputKBPS       float64
		TargetMatrix            bool
		AllowRemoteDNS          bool
	}{protocol, cfg.Targets, cfg.TargetRules, cfg.RequireText, cfg.RejectText, cfg.ExpectJSON, cfg.ExpectedBodySHA, cfg.ExpectCountries, cfg.PinSHA256, cfg.Repeat, cfg.RotationSamples, cfg.TargetQuorum, cfg.MinSuccessRate, cfg.MinResponseBytes, cfg.MinThroughputKBPS, cfg.TargetMatrix, cfg.AllowRemoteDNS})
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func writeCheckpointFingerprint(checkpointPath, fingerprint string) error {
	output, err := openSecureOutput(checkpointPath+checkpointConfigSuffix, true)
	if err != nil {
		return err
	}
	defer output.Abort()
	if err := output.WriteLine(fingerprint); err != nil {
		return err
	}
	return output.Commit()
}

// verifyCheckpointFingerprint treats a missing sidecar as a warning, because
// checkpoints written by earlier versions never had one.
func verifyCheckpointFingerprint(checkpointPath, fingerprint string, diagnostics io.Writer) error {
	payload, err := os.ReadFile(checkpointPath + checkpointConfigSuffix)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(diagnostics, "warning: checkpoint has no configuration fingerprint; verify it used the same validation rules")
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(payload)) != fingerprint {
		return errors.New("checkpoint was created with different validation rules; use the original settings or pass --resume-any-config")
	}
	return nil
}
