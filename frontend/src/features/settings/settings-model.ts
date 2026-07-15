import { z } from "zod";

import type { SettingsConfigDTO } from "@/features/settings/settings-api";

export type DurationUnit = "s" | "m" | "h" | "d";
export type DurationValue = { value: number; unit: DurationUnit };
export type ByteSizeUnit = "MiB" | "GiB";
export type ByteSizeValue = { value: number; unit: ByteSizeUnit };

const durationSchema = z.object({ value: z.number().positive(), unit: z.enum(["s", "m", "h", "d"]) });
const positiveInteger = z.number().int().positive();
const byteSizeSchema = z.object({ value: z.number().positive(), unit: z.enum(["MiB", "GiB"]) });
const routingTTLDuration = durationSchema.refine((value) => durationSeconds(value) <= 30 * 86_400);
const routingCooldownDuration = durationSchema.refine((value) => durationSeconds(value) <= 86_400);
const routingCapacityWaitDuration = durationSchema.refine((value) => durationSeconds(value) <= 5);
const auditFlushDuration = durationSchema.refine((value) => {
  const seconds = durationSeconds(value);
  return seconds >= 0.01 && seconds <= 60;
});
const consoleChatDuration = durationSchema.refine((value) => {
  const seconds = durationSeconds(value);
  return seconds >= 5 && seconds <= 30 * 60;
});

function validPublicAPIBaseURL(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;
  try {
    const parsed = new URL(trimmed);
    if (parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") return false;
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export const settingsSchema = z.object({
  server: z.object({
    maxConcurrentRequests: positiveInteger.max(100_000),
  }),
  providerBuild: z.object({
    baseURL: z.url(),
    clientVersion: z.string().trim().min(1),
    clientIdentifier: z.string().trim().min(1),
    tokenAuth: z.string().trim(),
    tokenAuthConfigured: z.boolean(),
    userAgent: z.string().trim().min(1),
  }).superRefine((value, context) => {
    if (!value.tokenAuthConfigured && value.tokenAuth.length === 0) {
      context.addIssue({ code: "custom", path: ["tokenAuth"], message: "required" });
    }
  }),
  providerWeb: z.object({
    baseURL: z.url().refine((value) => value.startsWith("https://")),
    statsigMode: z.enum(["manual", "url"]),
    statsigManualValue: z.string().trim().max(4096),
    statsigManualConfigured: z.boolean(),
    statsigSignerURL: z.string().trim().max(2048),
    quotaTimeout: durationSchema, chatTimeout: durationSchema, imageTimeout: durationSchema, videoTimeout: durationSchema,
    mediaConcurrency: positiveInteger.max(64), allowNSFW: z.boolean(),
    recoveryBackoffBase: durationSchema, recoveryBackoffMax: durationSchema,
  }).superRefine((value, context) => {
    if (durationSeconds(value.recoveryBackoffMax) < durationSeconds(value.recoveryBackoffBase)) {
      context.addIssue({ code: "custom", path: ["recoveryBackoffMax"], message: "invalid" });
    }
    if (value.statsigMode === "manual" && !value.statsigManualConfigured && value.statsigManualValue.length === 0) {
      context.addIssue({ code: "custom", path: ["statsigManualValue"], message: "required" });
    }
    if (value.statsigManualValue.length > 0 && !validStatsigID(value.statsigManualValue)) {
      context.addIssue({ code: "custom", path: ["statsigManualValue"], message: "invalid" });
    }
    if (value.statsigMode === "url") {
      if (!validStatsigSignerURL(value.statsigSignerURL)) {
        context.addIssue({ code: "custom", path: ["statsigSignerURL"], message: "invalid" });
      }
    }
  }),
  providerConsole: z.object({
    baseURL: z.url().refine((value) => value.startsWith("https://")),
    userAgent: z.string().trim().min(1).max(512),
    chatTimeout: consoleChatDuration,
  }),
  batch: z.object({
    importConcurrency: positiveInteger.max(50),
    conversionConcurrency: positiveInteger.max(50),
    syncConcurrency: positiveInteger.max(50),
    refreshConcurrency: positiveInteger.max(50),
    randomDelay: z.number().int().min(0).max(5_000),
  }),
  media: z.object({
    maxImageSize: byteSizeSchema.refine((value) => byteSizeBytes(value) >= 1 << 20 && byteSizeBytes(value) <= 32 << 20),
    maxTotalSize: byteSizeSchema.refine((value) => byteSizeBytes(value) <= 2 ** 40),
    cleanupThresholdPercent: z.number().int().min(50).max(95),
    cleanupInterval: durationSchema.refine((value) => durationSeconds(value) >= 60 && durationSeconds(value) <= 86_400),
  }).refine((value) => byteSizeBytes(value.maxTotalSize) >= byteSizeBytes(value.maxImageSize), { path: ["maxTotalSize"] }),
  frontend: z.object({
    publicApiBaseURL: z.string().trim().max(2048).refine((value) => validPublicAPIBaseURL(value), { message: "invalid" }),
  }),
  routing: z.object({
    stickyTTL: routingTTLDuration,
    cooldownBase: routingCooldownDuration,
    cooldownMax: routingCooldownDuration,
    capacityWait: routingCapacityWaitDuration,
    maxAttempts: positiveInteger.max(10),
  }).refine((value) => durationSeconds(value.cooldownMax) >= durationSeconds(value.cooldownBase), { path: ["cooldownMax"] }),
  audit: z.object({ bufferSize: positiveInteger.max(262_144), batchSize: positiveInteger.max(4_096), flushInterval: auditFlushDuration })
    .refine((value) => value.batchSize <= value.bufferSize, { path: ["batchSize"] }),
  clientKeyDefaults: z.object({ rpmLimit: positiveInteger.max(100_000), maxConcurrent: positiveInteger.max(1_024) }),
  autoRegister: z.object({
    enabled: z.boolean(),
    minAvailableWeb: z.number().int().min(0).max(10_000),
    targetAvailableWeb: z.number().int().min(0).max(10_000),
    maxConcurrent: positiveInteger.max(5),
    checkInterval: durationSchema.refine((value) => durationSeconds(value) >= 15 && durationSeconds(value) <= 86_400),
    registerTimeout: durationSchema.refine((value) => durationSeconds(value) >= 60 && durationSeconds(value) <= 30 * 60),
    sidecarURL: z.string().trim().max(2048),
    mailProvider: z.enum(["cloudflare", "yyds"]),
    mailApiBase: z.string().trim().max(2048),
    mailAdminKey: z.string().trim().max(512),
    mailAdminKeyConfigured: z.boolean(),
    mailAuthMode: z.string().trim().max(64),
    mailDomains: z.string().trim().max(2048),
    mailPathNewAddress: z.string().trim().max(256),
    mailPathMessages: z.string().trim().max(256),
    mailAutoDomains: z.boolean(),
    mailRandomSubdomain: z.boolean(),
    mailDomainStrategy: z.enum(["rotate", "random", "first"]),
    yydsAllowPublicDomains: z.boolean(),
    yydsJwt: z.string().trim().max(4096),
    yydsJwtConfigured: z.boolean(),
    captchaKey: z.string().trim().max(512),
    captchaKeyConfigured: z.boolean(),
    captchaEndpoint: z.string().trim().max(2048),
    captchaTimeout: durationSchema.refine((value) => durationSeconds(value) >= 30 && durationSeconds(value) <= 600),
    mailTimeout: durationSchema.refine((value) => durationSeconds(value) >= 30 && durationSeconds(value) <= 600),
    alsoImportConsole: z.boolean(),
    verifyBuildAfterRegister: z.boolean(),
    probeDelay: durationSchema.refine((value) => durationSeconds(value) >= 0 && durationSeconds(value) <= 600),
    probeModel: z.string().trim().max(128),
    fallbackProxyURL: z.string().trim().max(2048),
    skipCaptcha: z.boolean(),
  }).superRefine((value, context) => {
    if (value.targetAvailableWeb < value.minAvailableWeb) {
      context.addIssue({ code: "custom", path: ["targetAvailableWeb"], message: "invalid" });
    }
    if (value.enabled) {
      const isYyds = value.mailProvider === "yyds";
      if (!isYyds && !value.mailApiBase.trim()) {
        context.addIssue({ code: "custom", path: ["mailApiBase"], message: "required" });
      }
      // Cloud Temp Mail: domains optional when auto-fetch is on.
      if (!isYyds && !value.mailDomains.trim() && !value.mailAutoDomains) {
        context.addIssue({ code: "custom", path: ["mailDomains"], message: "required" });
      }
      // YYDS: self-hosted domain required unless user explicitly allows public (blacklisted).
      if (isYyds && !value.mailDomains.trim() && !value.yydsAllowPublicDomains) {
        context.addIssue({ code: "custom", path: ["mailDomains"], message: "required" });
      }
      const hasMailKey = value.mailAdminKeyConfigured || value.mailAdminKey.trim();
      const hasYydsJwt = value.yydsJwtConfigured || value.yydsJwt.trim();
      if (isYyds) {
        if (!hasMailKey && !hasYydsJwt) {
          context.addIssue({ code: "custom", path: ["mailAdminKey"], message: "required" });
        }
      } else if (!hasMailKey) {
        context.addIssue({ code: "custom", path: ["mailAdminKey"], message: "required" });
      }
      if (!value.skipCaptcha && !value.captchaKeyConfigured && !value.captchaKey.trim()) {
        context.addIssue({ code: "custom", path: ["captchaKey"], message: "required" });
      }
    }
  }),
});

export type SettingsForm = z.infer<typeof settingsSchema>;

export function toSettingsForm(config: SettingsConfigDTO): SettingsForm {
  return {
    server: config.server,
    providerBuild: { ...config.providerBuild, tokenAuth: "" },
    providerWeb: {
      ...config.providerWeb,
      statsigManualValue: "",
      quotaTimeout: parseDuration(config.providerWeb.quotaTimeout), chatTimeout: parseDuration(config.providerWeb.chatTimeout),
      imageTimeout: parseDuration(config.providerWeb.imageTimeout), videoTimeout: parseDuration(config.providerWeb.videoTimeout),
      recoveryBackoffBase: parseDuration(config.providerWeb.recoveryBackoffBase), recoveryBackoffMax: parseDuration(config.providerWeb.recoveryBackoffMax),
    },
    providerConsole: { ...config.providerConsole, chatTimeout: parseDuration(config.providerConsole.chatTimeout) },
    batch: { ...config.batch, randomDelay: parseDurationMilliseconds(config.batch.randomDelay) },
    media: {
      maxImageSize: parseByteSize(config.media.maxImageBytes), maxTotalSize: parseByteSize(config.media.maxTotalBytes),
      cleanupThresholdPercent: config.media.cleanupThresholdPercent,
      cleanupInterval: parseDuration(config.media.cleanupInterval),
    },
    frontend: {
      publicApiBaseURL: config.frontend.publicApiBaseURL,
    },
    routing: {
      stickyTTL: parseDuration(config.routing.stickyTTL), cooldownBase: parseDuration(config.routing.cooldownBase),
      cooldownMax: parseDuration(config.routing.cooldownMax), capacityWait: parseDuration(config.routing.capacityWait), maxAttempts: config.routing.maxAttempts,
    },
    audit: { bufferSize: config.audit.bufferSize, batchSize: config.audit.batchSize, flushInterval: parseDuration(config.audit.flushInterval) },
    clientKeyDefaults: config.clientKeyDefaults,
    autoRegister: {
      enabled: config.autoRegister?.enabled ?? false,
      minAvailableWeb: config.autoRegister?.minAvailableWeb ?? 5,
      targetAvailableWeb: config.autoRegister?.targetAvailableWeb ?? 10,
      maxConcurrent: config.autoRegister?.maxConcurrent ?? 1,
      checkInterval: parseDuration(config.autoRegister?.checkInterval || "1m"),
      registerTimeout: parseDuration(config.autoRegister?.registerTimeout || "8m"),
      sidecarURL: config.autoRegister?.sidecarURL ?? "http://127.0.0.1:8091",
      mailProvider: (config.autoRegister?.mailProvider === "yyds" ? "yyds" : "cloudflare") as "cloudflare" | "yyds",
      mailApiBase: config.autoRegister?.mailApiBase ?? "",
      mailAdminKey: "",
      mailAdminKeyConfigured: config.autoRegister?.mailAdminKeyConfigured ?? false,
      mailAuthMode: config.autoRegister?.mailAuthMode || "x-admin-auth",
      mailDomains: config.autoRegister?.mailDomains ?? "",
      mailPathNewAddress: config.autoRegister?.mailPathNewAddress || "/admin/new_address",
      mailPathMessages: config.autoRegister?.mailPathMessages || "/api/mails",
      mailAutoDomains: config.autoRegister?.mailAutoDomains ?? true,
      mailRandomSubdomain: config.autoRegister?.mailRandomSubdomain ?? true,
      mailDomainStrategy: (["rotate", "random", "first"].includes(config.autoRegister?.mailDomainStrategy || "")
        ? config.autoRegister?.mailDomainStrategy
        : "rotate") as "rotate" | "random" | "first",
      yydsAllowPublicDomains: config.autoRegister?.yydsAllowPublicDomains ?? false,
      yydsJwt: "",
      yydsJwtConfigured: config.autoRegister?.yydsJwtConfigured ?? false,
      captchaKey: "",
      captchaKeyConfigured: config.autoRegister?.captchaKeyConfigured ?? false,
      captchaEndpoint: config.autoRegister?.captchaEndpoint || "https://api.ez-captcha.com",
      captchaTimeout: parseDuration(config.autoRegister?.captchaTimeout || "3m"),
      mailTimeout: parseDuration(config.autoRegister?.mailTimeout || "2m"),
      alsoImportConsole: config.autoRegister?.alsoImportConsole ?? false,
      verifyBuildAfterRegister: config.autoRegister?.verifyBuildAfterRegister ?? true,
      probeDelay: parseDuration(config.autoRegister?.probeDelay || "30s"),
      probeModel: config.autoRegister?.probeModel || "grok-4.5",
      fallbackProxyURL: config.autoRegister?.fallbackProxyURL ?? "",
      skipCaptcha: config.autoRegister?.skipCaptcha ?? false,
    },
  };
}

export function toSettingsDTO(config: SettingsForm): SettingsConfigDTO {
  return {
    server: config.server,
    providerBuild: config.providerBuild,
    providerWeb: {
      ...config.providerWeb,
      quotaTimeout: formatDuration(config.providerWeb.quotaTimeout), chatTimeout: formatDuration(config.providerWeb.chatTimeout),
      imageTimeout: formatDuration(config.providerWeb.imageTimeout), videoTimeout: formatDuration(config.providerWeb.videoTimeout),
      recoveryBackoffBase: formatDuration(config.providerWeb.recoveryBackoffBase), recoveryBackoffMax: formatDuration(config.providerWeb.recoveryBackoffMax),
    },
    providerConsole: { ...config.providerConsole, chatTimeout: formatDuration(config.providerConsole.chatTimeout) },
    batch: { ...config.batch, randomDelay: `${config.batch.randomDelay}ms` },
    media: {
      maxImageBytes: byteSizeBytes(config.media.maxImageSize), maxTotalBytes: byteSizeBytes(config.media.maxTotalSize),
      cleanupThresholdPercent: config.media.cleanupThresholdPercent,
      cleanupInterval: formatDuration(config.media.cleanupInterval),
    },
    frontend: {
      publicApiBaseURL: config.frontend.publicApiBaseURL.trim(),
    },
    routing: {
      stickyTTL: formatDuration(config.routing.stickyTTL), cooldownBase: formatDuration(config.routing.cooldownBase),
      cooldownMax: formatDuration(config.routing.cooldownMax), capacityWait: formatDuration(config.routing.capacityWait), maxAttempts: config.routing.maxAttempts,
    },
    audit: { bufferSize: config.audit.bufferSize, batchSize: config.audit.batchSize, flushInterval: formatDuration(config.audit.flushInterval) },
    clientKeyDefaults: config.clientKeyDefaults,
    autoRegister: {
      ...config.autoRegister,
      checkInterval: formatDuration(config.autoRegister.checkInterval),
      registerTimeout: formatDuration(config.autoRegister.registerTimeout),
      captchaTimeout: formatDuration(config.autoRegister.captchaTimeout),
      mailTimeout: formatDuration(config.autoRegister.mailTimeout),
      sidecarURL: config.autoRegister.sidecarURL.trim(),
      mailProvider: config.autoRegister.mailProvider,
      mailApiBase: config.autoRegister.mailApiBase.trim(),
      mailDomains: config.autoRegister.mailDomains.trim(),
      mailAutoDomains: config.autoRegister.mailAutoDomains,
      mailRandomSubdomain: config.autoRegister.mailRandomSubdomain,
      mailDomainStrategy: config.autoRegister.mailDomainStrategy,
      yydsAllowPublicDomains: config.autoRegister.yydsAllowPublicDomains,
      captchaEndpoint: config.autoRegister.captchaEndpoint.trim(),
      fallbackProxyURL: config.autoRegister.fallbackProxyURL.trim(),
      probeDelay: formatDuration(config.autoRegister.probeDelay),
      probeModel: config.autoRegister.probeModel.trim(),
      verifyBuildAfterRegister: config.autoRegister.verifyBuildAfterRegister,
      skipCaptcha: config.autoRegister.skipCaptcha,
    },
  };
}

export function isDurationUnit(value: string): value is DurationUnit {
  return value === "s" || value === "m" || value === "h" || value === "d";
}

export function isByteSizeUnit(value: string): value is ByteSizeUnit {
  return value === "MiB" || value === "GiB";
}

function byteSizeBytes(value: ByteSizeValue): number {
  return Math.round(value.value * (value.unit === "GiB" ? 2 ** 30 : 2 ** 20));
}

function parseByteSize(bytes: number): ByteSizeValue {
  if (bytes >= 2 ** 30 && bytes % 2 ** 30 === 0) return { value: bytes / 2 ** 30, unit: "GiB" };
  return { value: bytes / 2 ** 20, unit: "MiB" };
}

function durationSeconds(value: DurationValue): number {
  const factors: Record<DurationUnit, number> = { s: 1, m: 60, h: 3_600, d: 86_400 };
  return value.value * factors[value.unit];
}

function formatDuration(value: DurationValue): string {
  if (value.unit === "d") return `${value.value * 24}h`;
  return `${value.value}${value.unit}`;
}

function parseDuration(value: string): DurationValue {
  const simple = value.match(/^(\d+(?:\.\d+)?)(ms|s|m|h)$/);
  if (simple) {
    const amount = Number(simple[1]);
    if (simple[2] === "ms") return { value: amount / 1000, unit: "s" };
    if (simple[2] === "h" && amount >= 24 && amount % 24 === 0) return { value: amount / 24, unit: "d" };
    if (isDurationUnit(simple[2])) return { value: amount, unit: simple[2] };
  }

  const factors: Record<string, number> = { ns: 0.000001, us: 0.001, "µs": 0.001, ms: 1, s: 1000, m: 60_000, h: 3_600_000 };
  const parts = [...value.matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g)];
  if (parts.map((part) => part[0]).join("") !== value || parts.length === 0) return { value: 1, unit: "s" };
  const milliseconds = parts.reduce((total, part) => total + Number(part[1]) * factors[part[2]], 0);
  const units: Array<[DurationUnit, number]> = [["d", 86_400_000], ["h", 3_600_000], ["m", 60_000], ["s", 1000]];
  for (const [unit, factor] of units) {
    const amount = milliseconds / factor;
    if (amount >= 1 && Number.isInteger(amount)) return { value: amount, unit };
  }
  return { value: milliseconds / 1000, unit: "s" };
}

function parseDurationMilliseconds(value: string): number {
  return Math.round(durationSeconds(parseDuration(value)) * 1000);
}

function validStatsigID(value: string): boolean {
  try {
    const normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    return atob(padded).length === 70;
  } catch {
    return false;
  }
}

function validStatsigSignerURL(value: string): boolean {
  try {
    const parsed = new URL(value);
    if (parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") return false;
    const internal = internalSignerHostname(parsed.hostname);
    if (internal) return parsed.protocol === "http:" || parsed.protocol === "https:";
    return parsed.protocol === "https:" && (parsed.port === "" || parsed.port === "443");
  } catch {
    return false;
  }
}

function internalSignerHostname(value: string): boolean {
  const host = value.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) return true;
  if (!host.includes(".")) {
    if (host.includes(":")) return host === "::1" || /^(?:fc|fd|fe[89ab])/i.test(host);
    return /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/i.test(host);
  }
  const octets = host.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  return octets[0] === 10 || octets[0] === 127 || octets[0] === 169 && octets[1] === 254 || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 || octets[0] === 192 && octets[1] === 168;
}
