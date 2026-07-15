# Security policy

## Upstream

This project is a fork of **[chenyme/grok2api](https://github.com/chenyme/grok2api)** (Author: [Chenyme](https://github.com/chenyme), MIT).

Report vulnerabilities that affect the **upstream gateway** to the upstream maintainers when possible. Report issues specific to the **auto-register sidecar / fork changes** via this repository’s Issues (do not open public issues with live secrets).

## What must never be committed

| Item | Safe location |
| --- | --- |
| `config.yaml` with real `jwtSecret` / encryption keys / admin password | Local only (gitignored) |
| Mail admin keys, YYDS JWT, captcha keys | Admin UI runtime settings (encrypted DB) |
| Proxy URLs with credentials | Egress nodes in admin UI |
| SSO tokens, OAuth exports, `sso_output/` | Local / encrypted account store |
| `services/auto_register/proxies.txt` with real proxies | Do not use for production; prefer admin egress |
| `.env` | Local only; use `.env.example` as template |

Use `config.example.yaml` and `.env.example` as public templates. Replace every placeholder before production.

## Hardening checklist (public deploy)

1. Generate strong `jwtSecret` and `credentialEncryptionKey` (see README).
2. Change `bootstrapAdmin` password immediately; remove the bootstrap block after first login.
3. Keep `server.swaggerEnabled: false` in production.
4. Do not expose admin UI or the auto-register sidecar (`:8091`) to the public Internet without auth / network policy.
5. Prefer HTTPS + `auth.secureCookies: true` behind a reverse proxy.
6. Rotate any key that may have leaked in chat logs, screenshots, or old private clones.

## Auto-register notes

- Temporary-mail **public shared domains** are often blocked by xAI; use self-hosted domains you control.
- Captcha and mail API keys are write-only in the admin API (stored encrypted).
- Sidecar progress logs may include email addresses; treat logs as sensitive.
