# Production Hardening Checklist

A consolidated, ordered checklist for deploying and operating the OIDC
Agent Compatibility Server in production. Each item distills a warning that
appears in more detail across the User Guide and the
[Threat Model](../reference/threat-model.md). Run through these **before**
you handle real provider keys.

> The [Docker: Production](./docker-prod.md#production-security-checklist)
> page has a deployment-specific checklist (certificates, secrets,
> networking) for the containerized central proxy. This page is the
> end-to-end umbrella checklist — use both.

> **Why it matters.** The most valuable asset is the **provider API key** —
> it is encrypted at rest in the central database, but an operator error
> (weak MEK, non-company PKI, group enforcement off) can weaken the whole
> security model. These checks close those gaps.

## Before deployment

> Certificates, secrets-in-transit, and networking specifics live in
> [Docker: Production — checklist](./docker-prod.md#production-security-checklist).
> This section covers the authorization- and key-handling items that page
> does not.

- [ ] **Request the `"groups"` scope on the relay.**
      Group-based policy enforcement and admin authorization require the
      relay's OIDC `scopes` to include `"groups"`:
      ```toml
      scopes = ["openid", "email", "profile", "groups"]
      ```
      Without it, central cannot see group memberships and **cannot enforce
      group policies or the admin group**.
- [ ] **Strong provider-key encryption key (MEK).**
      Use a cryptographically random MEK (e.g. `openssl rand -hex 32`) or a
      KMS-backed secret. Do **not** reuse a dev/test value you've committed
      anywhere.
- [ ] **Back up the MEK securely.**
      If the MEK is lost, the encrypted provider keys in the central DB
      become undecryptable. Store it in your secrets manager or separate
      hardware, with a tested recovery path.
- [ ] **Set a nonzero `rate_limit_requests` / window.**
      Defaults are `60` per 60s per client IP. Confirm they are appropriate
      for your traffic.

## After deployment

- [ ] **Admin API is protected by the IdP group.**
      Confirm your `admin_group` in the central `[admin]` section matches a
      real, tightly-scoped IdP group, and that **no one** is a member who
      should not be. There is no static admin token — the admin's OIDC
      identity is the auth.
- [ ] **Configure quotas and group policies for every group.**
      Use `oac-central admin policy-set` to bound models, endpoints, token
      and request quotas per group, so a single user cannot run up
      unbounded cost. See [Admin API](./admin-api.md).
- [ ] **Add provider keys without echo, never paste into a shell log.**
      Use `oac-central admin provider-key-add`, which reads the secret
      without echo. The key is stored AES-256-GCM encrypted (central must
      decrypt it to forward upstream) alongside a SHA-256 digest used to
      identify it. Key material is never returned by the admin API and
      never logged.
- [ ] **Verify the provider-key-leak test.**
      In the Docker dev stack, `./docker/dev.sh test` includes a leak
      check asserting `sk-mock-backend-master-key` never appears in the
      relay's `/v1/models` response body.
- [ ] **Monitor the audit log.**
      `oac-central admin audit-query` lets you review who accessed what,
      which models they used, token/cost totals, and permission decisions.
      Pick an interval and tell a human to review it.

## Ongoing operations

- [ ] **Re-login windows are intentional.**
      v1 stores no OIDC refresh tokens; central-minted tokens expire per
      the `--ttl` flag (default: never expires). Set
      `max_token_ttl_seconds` on group policies as an admin backstop.
      Users re-run `oac-relay login` when their token expires.
- [ ] **Audit dependency advisories.**
      `cargo audit` flags known transitive advisories (`rsa`,
      `rustls-pemfile`); track them in your own vulnerability process — do
      not ship unpatched advisories silently.
- [ ] **Practice MEK recovery.**
      Periodically confirm you can bring the MEK back and decrypt a
      provider key in a non-production environment.

See [Security for Users](./security.md) for the user-facing summary and
[Threat Model](../reference/threat-model.md) for the full STRIDE analysis.