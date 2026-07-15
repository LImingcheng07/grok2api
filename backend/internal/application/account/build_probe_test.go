package account

import "testing"

func TestClassifyBuildProbeErrorMarksChatDenial(t *testing.T) {
	status, dead := classifyBuildProbeError(403, `{"error":"Access to the chat endpoint is denied. Please update the permissions."}`)
	if status != 403 || !dead {
		t.Fatalf("chat denial: status=%d dead=%v", status, dead)
	}
	status, dead = classifyBuildProbeError(200, "")
	if dead {
		t.Fatalf("ok body should not be dead, status=%d", status)
	}
	status, dead = classifyBuildProbeError(401, "unauthorized")
	if status != 401 || !dead {
		t.Fatalf("401: status=%d dead=%v", status, dead)
	}
	// free-usage text alone without 401/403 should not force dead via auth keywords
	status, dead = classifyBuildProbeError(429, "subscription:free-usage-exhausted authentication note")
	if dead {
		t.Fatalf("free-usage should not be dead token: status=%d", status)
	}
}

func TestTruncateProbeText(t *testing.T) {
	if got := truncateProbeText("  hello  ", 10); got != "hello" {
		t.Fatalf("got %q", got)
	}
	if got := truncateProbeText(string(make([]byte, 50)), 10); len(got) != 10 {
		t.Fatalf("len=%d", len(got))
	}
}
