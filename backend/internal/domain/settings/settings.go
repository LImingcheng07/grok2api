package settings

import "time"

// Config 表示可跨重启持久化并支持热加载的网关运行参数。
type Config struct {
	Server            ServerConfig
	ProviderBuild     ProviderBuildConfig
	ProviderWeb       ProviderWebConfig
	ProviderConsole   ProviderConsoleConfig
	Batch             BatchConfig
	Media             MediaConfig
	Frontend          FrontendConfig
	Routing           RoutingConfig
	Audit             AuditConfig
	ClientKeyDefaults ClientKeyDefaultsConfig
	AutoRegister      AutoRegisterConfig
}

// AutoRegisterConfig 控制协议自动补号（Cloud Temp Mail / YYDS Mail + ez-captcha）。
// 出口代理从 grok_web 出口节点池随机轮训，保证每号随机 IP。
type AutoRegisterConfig struct {
	Enabled            bool
	MinAvailableWeb    int
	TargetAvailableWeb int
	MaxConcurrent      int
	CheckInterval      time.Duration
	RegisterTimeout    time.Duration
	SidecarURL         string
	// MailProvider: "cloudflare" (Cloud Temp Mail) or "yyds" (YYDS Mail https://vip.215.im/docs).
	MailProvider string
	MailAPIBase  string
	MailAdminKey string
	MailAuthMode string
	// MailDomains: comma-separated domains. YYDS: put your self-hosted domain(s) here
	// (public shared domains are often blocked by xAI). Cloud Temp Mail: optional when auto-fetch is on.
	MailDomains        string
	MailPathNewAddress string
	MailPathMessages   string
	// MailAutoDomains: Cloud Temp Mail — fetch domains from API and merge/fallback.
	MailAutoDomains bool
	// MailRandomSubdomain: Cloud Temp Mail enablePrefix / random local prefix.
	MailRandomSubdomain bool
	// MailDomainStrategy: rotate | random | first
	MailDomainStrategy string
	// YydsAllowPublicDomains: allow YYDS shared public domains (usually blacklisted by xAI).
	YydsAllowPublicDomains bool
	// YydsJWT optional Bearer JWT for YYDS (alternative to API Key).
	YydsJWT           string
	CaptchaKey        string
	CaptchaEndpoint   string
	CaptchaTimeout    time.Duration
	MailTimeout       time.Duration
	AlsoImportConsole bool
	FallbackProxyURL  string
	// SkipCaptcha attempts signup without Turnstile when true (clean residential IP may pass).
	SkipCaptcha bool
}

// ServerConfig 定义可热更新的推理入口容量参数。
type ServerConfig struct {
	MaxConcurrentRequests int
}

// FrontendConfig 定义公开 API 地址的运行时覆盖值；留空时使用配置文件值。
type FrontendConfig struct {
	PublicAPIBaseURL string
}

type ProviderConsoleConfig struct {
	BaseURL     string
	UserAgent   string
	ChatTimeout time.Duration
}

type MediaConfig struct {
	MaxImageBytes           int64
	MaxTotalBytes           int64
	CleanupThresholdPercent int
	CleanupInterval         time.Duration
}

type ProviderWebConfig struct {
	BaseURL             string
	StatsigMode         string
	StatsigManualValue  string
	StatsigSignerURL    string
	QuotaTimeout        time.Duration
	ChatTimeout         time.Duration
	ImageTimeout        time.Duration
	VideoTimeout        time.Duration
	MediaConcurrency    int
	AllowNSFW           bool
	RecoveryBackoffBase time.Duration
	RecoveryBackoffMax  time.Duration
}

// BatchConfig 定义账号导入、转换、同步和凭据刷新的并发上限。
type BatchConfig struct {
	ImportConcurrency     int
	ConversionConcurrency int
	SyncConcurrency       int
	RefreshConcurrency    int
	RandomDelay           *time.Duration
}

// ProviderBuildConfig 定义 Grok Build CLI 上游协议标识。
type ProviderBuildConfig struct {
	BaseURL          string
	ClientVersion    string
	ClientIdentifier string
	TokenAuth        string
	UserAgent        string
}

// RoutingConfig 定义会话粘性、冷却和故障切换边界。
type RoutingConfig struct {
	StickyTTL    time.Duration
	CooldownBase time.Duration
	CooldownMax  time.Duration
	CapacityWait time.Duration
	MaxAttempts  int
}

// AuditConfig 定义请求审计异步写入参数。
type AuditConfig struct {
	BufferSize    int
	BatchSize     int
	FlushInterval time.Duration
}

// ClientKeyDefaultsConfig 定义新建客户端密钥的默认限制。
type ClientKeyDefaultsConfig struct {
	RPMLimit      int
	MaxConcurrent int
}
