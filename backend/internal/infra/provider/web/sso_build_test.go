package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

type scriptedSSOClient struct {
	responses []*http.Response
	requests  []*http.Request
}

func (c *scriptedSSOClient) Do(request *http.Request) (*http.Response, error) {
	c.requests = append(c.requests, request)
	response := c.responses[0]
	c.responses = c.responses[1:]
	return response, nil
}

func TestSSOBuildFlowFollowsOnlyTrustedXAIHTTPSRedirects(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://auth.x.ai/next"}, "Set-Cookie": []string{"session=abc; Path=/; Secure"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	status, finalURL, body, err := flow.do(context.Background(), http.MethodGet, ssoAccountsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || finalURL != "https://auth.x.ai/next" || string(body) != "ok" {
		t.Fatalf("response = %d %s %q", status, finalURL, body)
	}
	if len(client.requests) != 2 || client.requests[1].Header.Get("User-Agent") != "test-agent" {
		t.Fatalf("requests = %#v", client.requests)
	}
	cookie := client.requests[1].Header.Get("Cookie")
	if !strings.Contains(cookie, "sso=secret") || !strings.Contains(cookie, "session=abc") {
		t.Fatalf("redirect cookies = %q", cookie)
	}

	unsafe := &scriptedSSOClient{responses: []*http.Response{{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://example.com/steal"}}, Body: io.NopCloser(strings.NewReader(""))}}}
	flow = &ssoBuildFlow{client: unsafe, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	if _, _, _, err := flow.do(context.Background(), http.MethodGet, ssoAccountsURL, nil); err == nil {
		t.Fatal("unsafe redirect was accepted")
	}
}

func TestSSOBuildConversionSanitizesTokenAndURLs(t *testing.T) {
	if token := normalizeSSOToken("sso=token-value; x-userid=drop"); token != "token-value" {
		t.Fatalf("token = %q", token)
	}
	for _, value := range []string{"https://accounts.x.ai/", "https://auth.x.ai/oauth2/device/code"} {
		if !safeXAIURL(value) {
			t.Fatalf("trusted URL rejected: %s", value)
		}
	}
	for _, value := range []string{"http://auth.x.ai/", "https://x.ai.example.com/", "https://user@auth.x.ai/"} {
		if safeXAIURL(value) {
			t.Fatalf("unsafe URL accepted: %s", value)
		}
	}
}

func TestRetrySSOBuildConversionRetriesOnlyRateLimits(t *testing.T) {
	t.Run("rate limited", func(t *testing.T) {
		calls := 0
		waits := 0
		seed, err := retrySSOBuildConversion(context.Background(), 6, func() (provider.CredentialSeed, error) {
			calls++
			if calls < 3 {
				return provider.CredentialSeed{}, errSSOBuildRateLimited
			}
			return provider.CredentialSeed{Name: "recovered"}, nil
		}, func(context.Context, int) error {
			waits++
			return nil
		})
		if err != nil || seed.Name != "recovered" || calls != 3 || waits != 2 {
			t.Fatalf("seed=%#v err=%v calls=%d waits=%d", seed, err, calls, waits)
		}
	})

	t.Run("permanent failure", func(t *testing.T) {
		calls := 0
		_, err := retrySSOBuildConversion(context.Background(), 6, func() (provider.CredentialSeed, error) {
			calls++
			return provider.CredentialSeed{}, errors.New("access denied")
		}, func(context.Context, int) error {
			t.Fatal("permanent failure waited for retry")
			return nil
		})
		if err == nil || calls != 1 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
}

func TestSSOBuildRateLimitDetection(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		url    string
	}{
		{status: http.StatusTooManyRequests},
		{status: http.StatusOK, body: `{"error":"slow_down"}`},
		{status: http.StatusOK, url: "https://auth.x.ai/rate_limited"},
	} {
		if !isSSOBuildRateLimited(test.status, test.url, []byte(test.body)) {
			t.Fatalf("rate limit not detected: %#v", test)
		}
	}
	if isSSOBuildRateLimited(http.StatusForbidden, "https://auth.x.ai/error", []byte("access denied")) {
		t.Fatal("403 access denied classified as a rate limit")
	}
}

func TestSSOBuildRetryDelayIsBounded(t *testing.T) {
	if delay := ssoBuildRetryDelay(1); delay != 2*time.Second {
		t.Fatalf("first delay = %s", delay)
	}
	if delay := ssoBuildRetryDelay(99); delay != 12*time.Second {
		t.Fatalf("bounded delay = %s", delay)
	}
}
