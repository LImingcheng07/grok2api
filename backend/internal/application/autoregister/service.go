package autoregister

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	settingsapp "github.com/chenyme/grok2api/backend/internal/application/settings"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

// Service keeps the Grok Web SSO pool topped up via the protocol sidecar.
// Each registration picks a random healthy egress proxy (random IP rotation).
// With no Grok Web egress nodes and empty fallbackProxyURL, registration uses direct (no proxy).
type Service struct {
	logger   *slog.Logger
	settings *settingsapp.Service
	accounts *accountapp.Service
	egress   repository.EgressRepository
	cipher   *security.Cipher
	client   *http.Client

	mu     sync.Mutex
	busy   atomic.Bool
	status Status

	// runCancel cancels the in-flight batch (run-once or scheduled tick workers).
	runCancel context.CancelFunc
	// stopRequested is set by Stop so workers exit between jobs even if cancel races.
	stopRequested atomic.Bool
}

type Status struct {
	Enabled            bool      `json:"enabled"`
	Running            bool      `json:"running"`
	Stopping           bool      `json:"stopping"`
	AvailableWeb       int64     `json:"availableWeb"`
	MinAvailableWeb    int       `json:"minAvailableWeb"`
	TargetAvailableWeb int       `json:"targetAvailableWeb"`
	LastCheckAt        time.Time `json:"lastCheckAt,omitempty"`
	LastSuccessAt      time.Time `json:"lastSuccessAt,omitempty"`
	LastError          string    `json:"lastError,omitempty"`
	LastEmail          string    `json:"lastEmail,omitempty"`
	LastProxy          string    `json:"lastProxy,omitempty"`
	// Phase is the current/last registration step (pick_proxy, create_mailbox, wait_email_code, ...).
	Phase string `json:"phase,omitempty"`
	// Progress is a human-readable one-line status for the UI.
	Progress string `json:"progress,omitempty"`
	// RecentLogs keeps the latest sidecar progress lines (newest last).
	RecentLogs   []string  `json:"recentLogs,omitempty"`
	SuccessCount int64     `json:"successCount"`
	FailureCount int64     `json:"failureCount"`
	InFlight     int       `json:"inFlight"`
	StartedAt    time.Time `json:"startedAt,omitempty"`
}

type registerResponse struct {
	OK       bool     `json:"ok"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	SSO      string   `json:"sso"`
	Proxy    string   `json:"proxy"`
	Error    string   `json:"error"`
	Logs     []string `json:"logs"`
	Phase    string   `json:"phase"`
	Progress string   `json:"progress"`
}

func NewService(logger *slog.Logger, settings *settingsapp.Service, accounts *accountapp.Service, egress repository.EgressRepository, cipher *security.Cipher) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		logger:   logger,
		settings: settings,
		accounts: accounts,
		egress:   egress,
		cipher:   cipher,
		client:   &http.Client{Timeout: 10 * time.Minute},
	}
}

func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.status
	out.Running = s.busy.Load()
	out.Stopping = s.stopRequested.Load() && out.Running
	// Reflect live toggle even between scheduler ticks.
	out.Enabled = s.settings.AutoRegisterRuntime().Enabled
	return out
}

// TriggerOnce runs a single refill cycle (works even when auto schedule is off).
// Skips if a batch is already running.
func (s *Service) TriggerOnce(ctx context.Context) {
	s.tick(ctx, true)
}

// Stop cancels the current batch. In-flight sidecar calls abort via context;
// remaining queued jobs are skipped. Safe to call when idle.
func (s *Service) Stop() {
	s.stopRequested.Store(true)
	s.mu.Lock()
	cancel := s.runCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.logger.Info("auto_register_stop_requested")
}

// Run is a supervised background loop.
func (s *Service) Run(ctx context.Context) {
	for {
		s.tick(ctx, false)
		cfg := s.settings.AutoRegisterRuntime()
		interval := cfg.CheckInterval.Value()
		if interval < 15*time.Second {
			interval = 15 * time.Second
		}
		// Cap sleep slices so enable/disable reacts within ~15s.
		deadline := time.Now().Add(interval)
		for time.Now().Before(deadline) {
			slice := 15 * time.Second
			if remain := time.Until(deadline); remain < slice {
				slice = remain
			}
			if slice <= 0 {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(slice):
			}
		}
	}
}

// tick runs one refill pass. force=true is used by "run once" so a manual shot
// works without leaving the auto schedule permanently enabled.
func (s *Service) tick(ctx context.Context, force bool) {
	cfg := s.settings.AutoRegisterRuntime()
	if !cfg.Enabled && !force {
		s.setStatus(func(st *Status) {
			st.Enabled = false
			st.LastCheckAt = time.Now().UTC()
		})
		return
	}
	if s.busy.Load() {
		return
	}
	if !s.busy.CompareAndSwap(false, true) {
		return
	}
	s.stopRequested.Store(false)
	runCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.runCancel = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		s.runCancel = nil
		s.mu.Unlock()
		s.busy.Store(false)
		s.stopRequested.Store(false)
	}()

	summary, err := s.accounts.Summary(runCtx)
	if err != nil {
		s.fail("summary", err.Error(), nil)
		return
	}
	available := summary.Providers[string(accountdomain.ProviderWeb)].Available
	minAvail := cfg.MinAvailableWeb
	if minAvail < 0 {
		minAvail = 0
	}
	target := cfg.TargetAvailableWeb
	if target < minAvail {
		target = minAvail
	}
	if force && target < 1 {
		target = 1
	}
	s.setStatus(func(st *Status) {
		st.Enabled = cfg.Enabled
		st.AvailableWeb = available
		st.MinAvailableWeb = minAvail
		st.TargetAvailableWeb = target
		st.LastCheckAt = time.Now().UTC()
	})
	// Scheduled mode: only top up when below min. Manual run-once always tries need.
	if !force && available >= int64(minAvail) {
		return
	}
	need := int(int64(target) - available)
	if force && need < 1 {
		need = 1
	}
	if need <= 0 {
		return
	}
	workers := cfg.MaxConcurrent
	if workers < 1 {
		workers = 1
	}
	if workers > 5 {
		workers = 5
	}
	if workers > need {
		workers = need
	}
	s.setStatus(func(st *Status) {
		st.Phase = "batch_start"
		st.Progress = fmt.Sprintf("starting batch need=%d workers=%d available=%d force=%v", need, workers, available, force)
		st.StartedAt = time.Now().UTC()
		st.RecentLogs = appendLog(st.RecentLogs, fmt.Sprintf(
			"[phase:batch_start] need=%d workers=%d available=%d target=%d force=%v",
			need, workers, available, target, force,
		))
	})
	s.logger.Info("auto_register_start", "available", available, "need", need, "workers", workers, "force", force)

	var wg sync.WaitGroup
	jobs := make(chan int, need)
	for i := 0; i < need; i++ {
		jobs <- i + 1
	}
	close(jobs)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				if runCtx.Err() != nil || s.stopRequested.Load() {
					return
				}
				// re-check mid-batch (scheduled mode only; force/run-once always registers)
				live := s.settings.AutoRegisterRuntime()
				if !force && !live.Enabled {
					return
				}
				// Only auto-schedule stops early when pool is already full.
				// "立即补号一次" must still call registerOne even if available >= target.
				if !force {
					sum, err := s.accounts.Summary(runCtx)
					if err == nil {
						if sum.Providers[string(accountdomain.ProviderWeb)].Available >= int64(live.TargetAvailableWeb) {
							s.setStatus(func(st *Status) {
								st.Progress = fmt.Sprintf("skip: available=%d already >= target=%d",
									sum.Providers[string(accountdomain.ProviderWeb)].Available, live.TargetAvailableWeb)
								st.RecentLogs = appendLog(st.RecentLogs,
									fmt.Sprintf("[phase:skip] available already at target=%d", live.TargetAvailableWeb))
							})
							return
						}
					}
				}
				s.registerOne(runCtx, live, index)
			}
		}()
	}
	wg.Wait()
	if s.stopRequested.Load() {
		s.setStatus(func(st *Status) {
			st.LastError = "stopped by user"
			st.Phase = "stopped"
			st.Progress = "stopped by user"
			st.RecentLogs = appendLog(st.RecentLogs, "[phase:stopped] stopped by user")
		})
		s.logger.Info("auto_register_stopped")
		return
	}
	s.setStatus(func(st *Status) {
		if st.Phase != "done" && st.Phase != "failed" && st.Phase != "skip" {
			st.Phase = "idle"
			st.Progress = "batch finished"
		}
		st.RecentLogs = appendLog(st.RecentLogs, "[phase:batch_done] batch finished")
	})
}

func (s *Service) registerOne(ctx context.Context, cfg config.AutoRegisterConfig, index int) {
	if ctx.Err() != nil || s.stopRequested.Load() {
		return
	}
	s.setStatus(func(st *Status) {
		st.InFlight++
		st.Phase = "pick_proxy"
		st.Progress = fmt.Sprintf("#%d picking proxy", index)
		st.RecentLogs = appendLog(st.RecentLogs, fmt.Sprintf("[phase:pick_proxy] #%d picking proxy", index))
	})
	defer s.setStatus(func(st *Status) {
		if st.InFlight > 0 {
			st.InFlight--
		}
	})

	proxy, proxyLabel, err := s.pickRandomProxy(ctx, cfg)
	if err != nil {
		s.fail("pick_proxy", err.Error(), nil)
		return
	}
	s.setStatus(func(st *Status) {
		st.LastProxy = proxyLabel
		st.Phase = "call_sidecar"
		st.Progress = fmt.Sprintf("#%d proxy=%s → sidecar", index, proxyLabel)
		st.RecentLogs = appendLog(st.RecentLogs, fmt.Sprintf("[phase:call_sidecar] #%d proxy=%s", index, proxyLabel))
	})
	timeout := cfg.RegisterTimeout.Value()
	if timeout < time.Minute {
		timeout = 8 * time.Minute
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	mailProvider := strings.ToLower(strings.TrimSpace(cfg.MailProvider))
	if mailProvider == "" {
		mailProvider = "cloudflare"
	}
	mailBase := strings.TrimSpace(cfg.MailAPIBase)
	if mailProvider == "yyds" && mailBase == "" {
		mailBase = "https://maliapi.215.im/v1"
	}
	strategy := strings.TrimSpace(cfg.MailDomainStrategy)
	if strategy == "" {
		strategy = "rotate"
	}
	payload := map[string]any{
		"index": index,
		"proxy": proxy,
		"config": map[string]any{
			"email_provider":                  mailProvider,
			"mail_provider":                   mailProvider,
			"cloudflare_api_base":             mailBase,
			"cloudflare_api_key":              cfg.MailAdminKey,
			"cloudflare_auth_mode":            firstNonEmpty(cfg.MailAuthMode, "x-admin-auth"),
			"cloudflare_path_accounts":        firstNonEmpty(cfg.MailPathNewAddress, "/admin/new_address"),
			"cloudflare_path_messages":        firstNonEmpty(cfg.MailPathMessages, "/api/mails"),
			"yyds_api_base":                   mailBase,
			"yyds_api_key":                    cfg.MailAdminKey,
			"yyds_jwt":                        cfg.YydsJWT,
			"yyds_allow_public_domains":       cfg.YydsAllowPublicDomains,
			"defaultDomains":                  cfg.MailDomains,
			"mail_domains":                    cfg.MailDomains,
			"mail_auto_domains":               cfg.MailAutoDomains,
			"mail_random_subdomain":           cfg.MailRandomSubdomain,
			"mail_domain_strategy":            strategy,
			"enablePrefix":                    cfg.MailRandomSubdomain,
			"email_proxy":                     "direct",
			"protocol_yescaptcha_key":         cfg.CaptchaKey,
			"protocol_yescaptcha_endpoint":    firstNonEmpty(cfg.CaptchaEndpoint, "https://api.ez-captcha.com"),
			"protocol_yescaptcha_timeout_sec": int(cfg.CaptchaTimeout.Value().Seconds()),
			"protocol_mail_timeout_sec":       int(cfg.MailTimeout.Value().Seconds()),
			"mail_poll_interval":              2,
			"skip_captcha":                    cfg.SkipCaptcha,
		},
	}
	body, _ := json.Marshal(payload)
	sidecar := strings.TrimRight(strings.TrimSpace(cfg.SidecarURL), "/")
	if sidecar == "" {
		sidecar = "http://127.0.0.1:8091"
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, sidecar+"/v1/register", bytes.NewReader(body))
	if err != nil {
		s.fail("call_sidecar", err.Error(), nil)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	s.setStatus(func(st *Status) {
		st.Phase = "registering"
		st.Progress = fmt.Sprintf("#%d registering via sidecar…", index)
	})
	resp, err := s.client.Do(req)
	if err != nil {
		if reqCtx.Err() != nil && s.stopRequested.Load() {
			return
		}
		if reqCtx.Err() != nil {
			s.fail("cancelled", "cancelled: "+err.Error(), nil)
			return
		}
		s.fail("sidecar", "sidecar: "+err.Error(), nil)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result registerResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		s.fail("sidecar", fmt.Sprintf("sidecar invalid json HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200)), nil)
		return
	}
	// Merge sidecar logs into live status even on failure.
	if len(result.Logs) > 0 {
		s.setStatus(func(st *Status) {
			for _, line := range result.Logs {
				st.RecentLogs = appendLog(st.RecentLogs, line)
			}
			if phase := strings.TrimSpace(result.Phase); phase != "" {
				st.Phase = phase
			} else if last := lastPhaseFromLogs(result.Logs); last != "" {
				st.Phase = last
			}
			if prog := strings.TrimSpace(result.Progress); prog != "" {
				st.Progress = prog
			} else if len(result.Logs) > 0 {
				st.Progress = result.Logs[len(result.Logs)-1]
			}
			if email := strings.TrimSpace(result.Email); email != "" {
				st.LastEmail = email
			}
		})
	}
	if resp.StatusCode >= 300 || !result.OK || strings.TrimSpace(result.SSO) == "" {
		msg := result.Error
		if msg == "" {
			msg = truncate(string(raw), 240)
		}
		phase := firstNonEmpty(result.Phase, lastPhaseFromLogs(result.Logs), "failed")
		s.fail(phase, msg, result.Logs)
		return
	}
	sso := strings.TrimSpace(result.SSO)
	if strings.HasPrefix(sso, "sso=") {
		sso = strings.TrimPrefix(sso, "sso=")
	}
	name := strings.TrimSpace(result.Email)
	if name == "" {
		name = "auto-" + time.Now().UTC().Format("150405")
	}
	s.setStatus(func(st *Status) {
		st.Phase = "import_web"
		st.Progress = fmt.Sprintf("#%d importing SSO for %s", index, name)
		st.RecentLogs = appendLog(st.RecentLogs, fmt.Sprintf("[phase:import_web] #%d email=%s", index, name))
	})
	document, _ := json.Marshal(map[string]any{
		"provider": string(accountdomain.ProviderWeb),
		"accounts": []map[string]string{{
			"name":      name,
			"sso_token": sso,
			"tier":      "auto",
		}},
	})
	importResult, err := s.accounts.ImportWebCredentials(reqCtx, document)
	if err != nil {
		s.fail("import_web", "import web: "+err.Error(), result.Logs)
		return
	}
	if cfg.AlsoImportConsole {
		consoleDoc, _ := json.Marshal(map[string]any{
			"provider": string(accountdomain.ProviderConsole),
			"accounts": []map[string]string{{
				"name":      name,
				"sso_token": sso,
			}},
		})
		if _, err := s.accounts.ImportConsoleCredentials(reqCtx, consoleDoc); err != nil {
			s.logger.Warn("auto_register_console_import_failed", "error", err, "email", name)
		}
	}
	s.setStatus(func(st *Status) {
		st.LastSuccessAt = time.Now().UTC()
		st.LastError = ""
		st.LastEmail = name
		st.LastProxy = proxyLabel
		st.Phase = "done"
		st.Progress = fmt.Sprintf("#%d success %s via %s", index, name, proxyLabel)
		st.SuccessCount++
		st.RecentLogs = appendLog(st.RecentLogs, fmt.Sprintf("[phase:done] #%d success email=%s proxy=%s", index, name, proxyLabel))
	})
	s.logger.Info("auto_register_success", "email", name, "proxy", proxyLabel, "imported", importResult.Created+importResult.Updated, "account_ids", importResult.AccountIDs)
}

func (s *Service) pickRandomProxy(ctx context.Context, cfg config.AutoRegisterConfig) (proxyURL, label string, err error) {
	nodes, listErr := s.egress.ListEgressNodes(ctx, egressdomain.ScopeWeb, repository.SortQuery{})
	if listErr != nil {
		return "", "", listErr
	}
	now := time.Now().UTC()
	candidates := make([]egressdomain.Node, 0, len(nodes))
	for _, node := range nodes {
		if !node.Enabled || strings.TrimSpace(node.EncryptedProxyURL) == "" {
			continue
		}
		if node.CooldownUntil != nil && now.Before(*node.CooldownUntil) {
			continue
		}
		candidates = append(candidates, node)
	}
	// No healthy Grok Web egress → optional fallback → otherwise direct (US VPS needs no proxy).
	if len(candidates) == 0 {
		fallback := strings.TrimSpace(cfg.FallbackProxyURL)
		if fallback == "" {
			return "", "direct", nil
		}
		return fallback, "fallback", nil
	}
	// crypto/rand pick for IP rotation across the unified egress pool.
	n, randErr := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if randErr != nil {
		var b [8]byte
		_, _ = rand.Read(b[:])
		idx := int(binary.BigEndian.Uint64(b[:]) % uint64(len(candidates)))
		n = big.NewInt(int64(idx))
	}
	selected := candidates[int(n.Int64())]
	proxy, decErr := s.cipher.Decrypt(selected.EncryptedProxyURL)
	if decErr != nil {
		return "", "", decErr
	}
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		return "", selected.Name + "/empty", nil
	}
	return proxy, selected.Name, nil
}

func (s *Service) fail(phase, message string, logs []string) {
	s.setStatus(func(st *Status) {
		st.LastError = truncate(message, 400)
		st.FailureCount++
		if strings.TrimSpace(phase) != "" {
			st.Phase = phase
		} else {
			st.Phase = "failed"
		}
		st.Progress = truncate(message, 240)
		for _, line := range logs {
			st.RecentLogs = appendLog(st.RecentLogs, line)
		}
		st.RecentLogs = appendLog(st.RecentLogs, "[phase:failed] "+truncate(message, 200))
	})
	s.logger.Warn("auto_register_failed", "phase", phase, "error", message)
}

func (s *Service) setStatus(update func(*Status)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	update(&s.status)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func appendLog(logs []string, line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return logs
	}
	const maxLogs = 40
	logs = append(logs, line)
	if len(logs) > maxLogs {
		logs = logs[len(logs)-maxLogs:]
	}
	return logs
}

func lastPhaseFromLogs(logs []string) string {
	for i := len(logs) - 1; i >= 0; i-- {
		line := logs[i]
		const marker = "[phase:"
		if idx := strings.Index(line, marker); idx >= 0 {
			rest := line[idx+len(marker):]
			if end := strings.Index(rest, "]"); end > 0 {
				return strings.TrimSpace(rest[:end])
			}
		}
	}
	return ""
}
