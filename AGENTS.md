# AGENTS.md

# Repository Overview

**CloudflareJwtValidator** — a single-project .NET library (NuGet package `CloudflareJwtValidator`) providing ASP.NET Core middleware that validates the JWT Cloudflare Zero Trust injects into proxied requests. It verifies the token signature from the `Cf-Access-Jwt-Assertion` header against Cloudflare's public signing keys and (optionally) checks that the `Cf-Access-Authenticated-User-Email` header matches the token's `email` claim.

- Solution: `CloudflareJwtValidator.sln` (1 project).
- Project: `CloudflareJwtValidator.csproj` — `netstandard2.1`, `ImplicitUsings` **disabled**, `Nullable` enabled, `TreatWarningsAsErrors`, `GeneratePackageOnBuild`. License GPL-3.0-or-later.
- Key packages: `Microsoft.AspNetCore.Http.Abstractions`, `Microsoft.Extensions.DependencyInjection.Abstractions`, `Microsoft.Extensions.Http`, `System.IdentityModel.Tokens.Jwt`.

## How it works

1. Consumers call `builder.Services.AddCloudflareJwtValidation()` (registers a typed `HttpClient` for the middleware) and `app.UseCloudflareJwtValidationMiddleware(config)`.
2. `CloudflareJwtValidationMiddleware.Invoke` runs per request:
   - `IsTokenValidationRequired` checks the request host/path against the configured `HostnameMatchSettings` / `PathMatchSettings`. If not required, the request passes through. Hostname matching uses `HostString.Host` (host only, port ignored); path matching uses the request path (no query string).
   - Otherwise `HasValidJwtToken` reads the `Cf-Access-Jwt-Assertion` header, optionally requires the email header, fetches/caches Cloudflare's signing keys, and validates the token.
   - On failure it writes `FailedResponseStatusCode` (default 403) and `FailedResponseBody`; it does **not** call the next middleware.
3. Signing keys are fetched from `{JwtIssuer}/cdn-cgi/access/certs` (per-request timeout `KeyRequestTimeout`, default 10s, via a `CancellationTokenSource`), cached in a static tuple for `KeyCacheTime` (default 12h), and refreshed under a `SemaphoreSlim` to prevent concurrent refreshes. If validation fails with `SecurityTokenSignatureKeyNotFoundException` (an unknown `kid`, e.g. just after Cloudflare rotates keys), the keys are force-refreshed — bypassing the TTL but rate-limited by `MinKeyRefreshInterval` (default 5 min) — and validation is retried once.
4. Token validation (`ValidateJwtToken`) parses the token **once** via `JwtSecurityTokenHandler.ValidateTokenAsync`: all cached `RsaSecurityKey`s are supplied as `IssuerSigningKeys` so the handler selects the right one by the token's `kid` header, and it validates issuer/audience/signature/algorithm (malformed/unverifiable tokens return an invalid result rather than throwing). When `ValidateAuthenticatedEmail` is set, the `email` claim is compared afterwards against the header, read from the validated `ClaimsIdentity` (handler configured with `MapInboundClaims = false`).

## Known limitations

- **Single configuration per process.** `Config` and the key cache are `static`; `UseCloudflareJwtValidationMiddleware` is last-write-wins, so multiple issuers/audiences in one app aren't supported. Accepted trade-off for this small library.
- **Logged visitor IP is spoofable** (read from `Cf-Connecting-Ip`/`X-Forwarded-For`/`X-Real-IP`) — diagnostics only, not authoritative.

Both are documented in `README.md` under "Limitations".

## Layout

- `CloudflareJwtValidationMiddleware.cs` — core middleware: request pipeline, key caching, token validation. Config is set via a static `internal` property by the extension method. Logs via injected `ILogger<CloudflareJwtValidationMiddleware>`: failed validations at the configurable `FailedValidationLogLevel` (default `Warning`), key-fetch failures at `Error`, per-request traces at `Debug`.
- `CloudflareJwtValidationExtensions.cs` — `AddCloudflareJwtValidation()` service registration (typed `HttpClient`).
- `Extensions/`
  - `CloudflareJwtValidationMiddlewareExtensions.cs` — `UseCloudflareJwtValidationMiddleware(config)`.
  - `CloudflareJwtCertificateExtensions.cs` — converts Cloudflare PEM certs to `RsaSecurityKey`s: extracts the RSA public-key parameters and disposes the `X509Certificate2`/`RSA` immediately (so no native handles are pinned for the cache's lifetime).
  - `HttpContextExtensions.cs` — request path formatting and proxied visitor IP resolution (`Cf-Connecting-Ip` → `X-Forwarded-For` → `X-Real-IP` → remote IP).
- `Models/`
  - `CloudflareJwtValidatorConfig.cs` — public config: `AppAud`, `JwtIssuer` (must be `https://`), match settings, `FailedResponseBody`/`StatusCode`, `FailedValidationLogLevel`, `CanIncludePiiInLogs` (redacts the user email in logs when false, the default), `KeyCacheTime`, `KeyRequestTimeout`, `MinKeyRefreshInterval`, `ValidateAuthenticatedEmail`.
  - `StringMatchSettings.cs` — `Include`/`Exclude` matching (`MatchingMode`) via regexes or wildcard (`*`) patterns; helpers `IncludeAll`, `ExcludeAll`, `IncludeAllExcept`, `ExcludeAllExcept`. String patterns are anchored at both ends (`^…$`, v4) — exact whole-value match unless `*` wildcards are used; raw `Regex` patterns are used as-is (not anchored).
  - `CloudflareJwtResponse.cs`, `CloudflareJwtKey.cs`, `CloudflareJwtCertificate.cs` — DTOs (`System.Text.Json`) for the `/cdn-cgi/access/certs` response. Only `public_certs` is required on deserialization; `keys` and `public_cert` are optional (modeled but unused). `public_certs` are turned into cached `RsaSecurityKey`s (see `CloudflareJwtCertificateExtensions`).

## Build & CI

- Build: `dotnet build --configuration Release` (also produces the NuGet package). Open `CloudflareJwtValidator.sln`.
- CI: `.github/workflows/build.yml` runs on push/PR to `master` — installs .NET 8, `dotnet build --configuration Release`.
- There is no test project.

## Conventions

- **Explicit usings** (`ImplicitUsings` disabled). Group usings by origin (System / project / third-party) separated by blank lines, matching existing files.
- **Constant fields prefixed `k`** (e.g. `kCloudflareJwtHeader`, `kCloudflareEmailHeader`, `kPatternWildcard`).
- **Boolean/predicate members start with `Is`/`Has`/`Can`** (e.g. `IsMatch`, `HasValidJwtToken`, `IsTokenValidationRequired`).
- Nullable reference types enabled; validate constructor args and throw `ArgumentException`/`ArgumentNullException` early (see the model DTOs).
- `TreatWarningsAsErrors` — warnings break the build; keep it clean.
- Public API surface is documented with XML doc comments; keep new public members documented.

See `README.md` for usage examples and `README.nuget.md` for the packaged readme.

# JWT & Cloudflare Access reference

Background distilled from RFC 7519 (JWT), RFC 7515 (JWS), RFC 7518 (JWA), RFC 7516 (JWE), and the Cloudflare Access docs. Kept here so future sessions don't need to re-fetch.

## JWT / JOSE essentials

- A **JWT** (RFC 7519) is a claims container, always serialized as either a **JWS** (signed — RFC 7515) or **JWE** (encrypted — RFC 7516). Cloudflare Access issues **signed JWTs (JWS compact serialization)**, which is all this library handles.
- **Compact serialization:** `BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)` (3 parts; a JWE has 5). Signing input is `ASCII(header '.' payload)`.
- **JOSE header params** (RFC 7515 §4): `alg` (MUST be present and understood), `kid` (key hint — matched here against the certs' `kid`), plus `jku`, `jwk`, `x5u`, `x5c`, `x5t`/`x5t#S256`, `typ`, `cty`, `crit` (unknown `crit` params MUST cause rejection).
- **Registered claims** (RFC 7519 §4.1, all OPTIONAL): `iss`, `sub`, `aud` (recipient MUST reject if it doesn't identify itself in `aud`), `exp`, `nbf`, `iat`, `jti`. Times are `NumericDate` (seconds since Unix epoch). `iss`/`aud` compared case-sensitively.
- **Signature algorithms** (RFC 7518 §3.1): `HS256` (Required), `RS256`/`ES256` (Recommended), `none` (Optional, empty signature — never accept unless intended). Cloudflare Access uses **RS256** (RSASSA-PKCS1-v1_5 + SHA-256, RSA key ≥2048 bits).
- **Validation vs verification** (jwt.io): *validation* = structure/format/claim checks (`exp`/`nbf`); *verification* = signature authenticity + `iss` + `aud`. This library relies on `JwtSecurityTokenHandler.ValidateTokenAsync` for `exp`/`nbf` and does signature/`iss`/`aud`/`email` itself.
- **Key security notes:** trust requires the signing key be verifiably the issuer's (RFC 7519 §11.1); the recipient — not the token's `alg` header — decides which algorithms are acceptable, preventing `alg:none` / algorithm-substitution attacks (RFC 7515 §10.6, RFC 7518 §8.5).

## Cloudflare Access specifics (what this library targets)

- Access injects the token as the **`Cf-Access-Jwt-Assertion`** request header (and, for browsers, a `CF_Authorization` cookie). Cloudflare **recommends validating the header**, since the cookie isn't guaranteed to be passed — this library uses the header only.
- Signing keys live at **`https://<team-name>.cloudflareaccess.com/cdn-cgi/access/certs`**. The response has: `keys` (both keys, JWK format), `public_cert` (current key, PEM), `public_certs` (both keys, PEM).
- **Correct key handling (matches this library):** Cloudflare warns *not* to use `public_cert` (a stale cache may serve an expired value); instead match the JWT's `kid` against `public_certs`. This library deserializes `public_certs` and matches by `kid` — which is why the JWK `keys`/single `public_cert` are modeled but unused.
- **Key rotation:** every 6 weeks by default; the previous key stays valid for 7 days. This is why keys are fetched from the live endpoint and cached (`KeyCacheTime`, default 12h) rather than hard-coded.
- `iss` = team domain (`https://<team-name>.cloudflareaccess.com`); `aud` = the per-application **AUD tag** from the Zero Trust dashboard (never changes unless the app is recreated). These map to `Config.JwtIssuer` / `Config.AppAud`.
- The `email` claim ↔ `Cf-Access-Authenticated-User-Email` header cross-check (`ValidateAuthenticatedEmail`) is a **defensive extra** this library adds; Cloudflare's own examples verify only signature + `iss` + `aud`.
- **Algorithm pinning:** `ValidateJwtToken` sets `ValidAlgorithms = { SecurityAlgorithms.RsaSha256 }` (RS256) on the `TokenValidationParameters`, matching Cloudflare's official examples and explicitly preventing `alg`-substitution / `alg:none` attacks (RFC 7515 §10.6, RFC 7518 §8.5). If Cloudflare ever changes its signing algorithm, this allow-list must be updated.
- **Not to be confused with API Shield JWT validation** (`/api-shield/security/jwt-validation/`): that validates *your own IdP's* JWTs at Cloudflare's edge (paste a JWKS, config via dashboard). Access instead mints its own token that *your origin* validates — the flow this library implements.

# Agent guidelines

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- Don't start answers with "great question" or "here's a possible solution" — just answer.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.
