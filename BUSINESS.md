# Business Model

## Strategy

The core software is open source. The business is the hosted service, native mobile apps, and team features built around it.

Open source drives adoption, trust, and community contributions. Revenue comes from convenience, premium features, and team/enterprise needs that self-hosters don't get for free.

## Open source (this repo, MIT)

- CLI binary (`terminal-relay`)
- Relay server (`terminal-relay-server`)
- Core protocol and crypto (`terminal-relay-core`)
- Web client (`terminal-relay-web`)

Users can self-host everything. The protocol and crypto are fully auditable.

## Closed source (separate repos)

- **terminal-relay-ios** — Native iOS app with speech-to-code, APNS push notifications, on-device speech recognition
- **terminal-relay-android** — Native Android app with speech-to-code, FCM push notifications, on-device ML Kit
- **terminal-relay-cloud** — Billing, account management, team dashboard, admin UI, SSO integrations, usage analytics, infrastructure/deployment configs

## Pricing tiers

| Tier | Price       | Includes                                                                                                  |
| ---- | ----------- | --------------------------------------------------------------------------------------------------------- |
| Free | $0          | 1 concurrent session, hosted relay, web client, 24h session TTL                                           |
| Pro  | ~$x/mo      | Unlimited sessions, native mobile apps, push notifications, session history, extended TTL, priority relay |
| Team | ~$x/user/mo | Everything in Pro + shared sessions, team dashboard, SSO, audit logs, admin controls                      |

## Revenue layers

1. **Hosted relay** — Free tier gets users in, paid tiers remove limits and add features
2. **Native mobile apps** — Speech-to-code is a premium differentiator, available on Pro and above
3. **Team features** — Shared sessions, permissions, audit logs, SSO for organizations
4. **Priority infrastructure** — Dedicated relay capacity, lower latency, SLA guarantees for paying users

## Repo structure

```text
terminal-relay/                  (open source, MIT)
├── crates/
│   ├── terminal-relay-core/
│   ├── terminal-relay-server/
│   └── terminal-relay-cli/
└── web/                         (future: web client)

terminal-relay-ios/              (closed source)
terminal-relay-android/          (closed source)
terminal-relay-cloud/            (closed source)
├── billing/
├── accounts/
├── team-management/
├── infra/
└── analytics/
```

## Key principles

- **Free tier is genuinely useful.** One session with full encryption is enough for individual use. No crippling.
- **Open source builds trust.** Users read the crypto code. Security researchers audit it. Contributors improve it.
- **Self-hosting is allowed.** Anyone can run their own relay. The hosted service competes on convenience, not lock-in.
- **Mobile apps are the premium hook.** Speech-to-code is something the web client and CLI cannot replicate well. This justifies the paid tier.
- **Team features scale revenue.** Per-seat pricing on team/enterprise is where the real money is.
