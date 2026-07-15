package autoregister

import (
	"errors"
	"testing"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
)

func TestProbeDisposition(t *testing.T) {
	tests := []struct {
		name  string
		probe accountapp.BuildProbeResult
		err   error
		want  probeDisposition
	}{
		{name: "success stays", probe: accountapp.BuildProbeResult{OK: true, StatusCode: 200}, want: probeKeep},
		{name: "403 is deleted", probe: accountapp.BuildProbeResult{StatusCode: 403, DeadToken: true}, want: probeDelete},
		{name: "401 is deleted", probe: accountapp.BuildProbeResult{StatusCode: 401}, want: probeDelete},
		{name: "rate limit is quarantined", probe: accountapp.BuildProbeResult{StatusCode: 429}, want: probeQuarantine},
		{name: "server error is quarantined", probe: accountapp.BuildProbeResult{StatusCode: 503}, want: probeQuarantine},
		{name: "transport error is quarantined", err: errors.New("network timeout"), want: probeQuarantine},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := decideProbeDisposition(test.probe, test.err); got != test.want {
				t.Fatalf("disposition = %v, want %v", got, test.want)
			}
		})
	}
}

func TestBatchAttemptCountIsBoundedByWorkers(t *testing.T) {
	if got := batchAttemptCount(500, 5); got != 5 {
		t.Fatalf("batchAttemptCount(500, 5) = %d, want 5", got)
	}
	if got := batchAttemptCount(2, 5); got != 2 {
		t.Fatalf("batchAttemptCount(2, 5) = %d, want 2", got)
	}
}

func TestAutoRegisterRequiresBuildVerification(t *testing.T) {
	cfg := config.AutoRegisterConfig{Enabled: true, VerifyBuildAfterRegister: false}
	if err := validateRefillConfig(cfg); err == nil {
		t.Fatal("enabled auto-register accepted disabled Build verification")
	}
	cfg.VerifyBuildAfterRegister = true
	if err := validateRefillConfig(cfg); err != nil {
		t.Fatalf("valid refill config rejected: %v", err)
	}
}

func TestFinishBatchStatusPreservesActionableFailure(t *testing.T) {
	status := Status{Phase: "probe_build", Progress: "upstream timeout", LastError: "upstream timeout"}
	finishBatchStatus(&status)
	if status.Phase != "probe_build" || status.Progress != "upstream timeout" {
		t.Fatalf("failure status was overwritten: %#v", status)
	}
}
