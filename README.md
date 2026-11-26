# Cloudflare JWT Validator

[![Nuget](https://img.shields.io/nuget/v/CloudflareJwtValidator.svg)](https://www.nuget.org/packages/CloudflareJwtValidator)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-yellow.svg)](https://opensource.org/license/gpl-3-0)
[![Build](https://github.com/delebru/CloudflareJwtValidator.NET/actions/workflows/build.yml/badge.svg)](https://github.com/delebru/CloudflareJwtValidator.NET/actions/workflows/build.yml)

Middleware for simple JWT (JSON Web Token) validation on web apps behind Cloudflare Zero Trust. This middleware will ensure requests to the web app are sent by Cloudflare by validating the token signature (RS256) under the `Cf-Access-Jwt-Assertion` header, and ensure the `Cf-Access-Authenticated-User-Email` user email matches the token's user email. 

The middleware will by default apply verification to all hostnames and paths but can be configured to include or exclude certain hostnames or paths. 

For more information on Cloudflare's JWT validation see: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/

## Required configuration variables
These should be loaded from app settings or env variables. The usage examples below have them hard coded but don't do that.

- Application Audience (AUD): secret 64 character alphanumeric string

https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/#get-your-aud-tag

- Issuer: `https://<team-domain>.cloudflareaccess.com`

To get your team's domain, go to Cloudflare's Zero Trust Dashboard > Settings > Custom Pages, and look for `Team domain`. Browsing to https://<team-domain>.cloudflareaccess.com/cdn-cgi/access/certs

## Basic usage
Without any hostname or path filtering settings passed to the `CloudflareJwtValidatorConfig`, the middleware will enforce a valid JWT token for all requests.

@ Program.cs:
```
using CloudflareJwtValidator.Extensions;

(...)

builder.Services.AddHttpClient(); // required by Cloudflare JWT Validator to download https://<team-domain>.cloudflareaccess.com/cdn-cgi/access/certs

(...)

var app = builder.Build();

app.UseForwardedHeaders(); // required by Cloudflare JWT Validator to log the visitor's source IP address

var cloudflareApplicationAudience = "<your-application-audience>";
var cloudflareTeamDomain = "https://<team-domain>.cloudflareaccess.com";
app.UseCloudflareJwtValidationMiddleware(new(cloudflareApplicationAudience, cloudflareTeamDomain));

(...) // other middlewares should go after JWT validation

app.Run();
```


## Advanced usage
A combination of string matching patterns for hostnames and/or paths can be passed to the `CloudflareJwtValidatorConfig` object. For example, if your app is behind a proxy receiving request from multiple hostnames, you may want to validate the tokens only from certain hostnames.


In the example below, the middleware will ignore JWT headers on all requests when the request hostname is `internal.domain.com`, and will also only check for valid JWT headers if the path starts with `/admin/` (see [Pattern matching](#pattern-matching) below for the `*` wildcard semantics).

@ Program.cs:
```
using CloudflareJwtValidator.Extensions;
using CloudflareJwtValidator.Models;

(...)

builder.Services.AddHttpClient(); // required by Cloudflare JWT Validator to download https://<team-domain>.cloudflareaccess.com/cdn-cgi/access/certs

(...)

var app = builder.Build();

app.UseForwardedHeaders(); // required by Cloudflare JWT Validator to log the visitor's source IP address

var cloudflareApplicationAudience = "<your-application-audience>";
var cloudflareTeamDomain = "https://<team-domain>.cloudflareaccess.com";
var hostnameMatchSettings = new StringMatchSettings(MatchingMode.Exclude, "internal.domain.com");
var pathMatchSettings = new StringMatchSettings(MatchingMode.Include, "/admin/*");

var cloudflareJwtValidatorConfig = new CloudflareJwtValidatorConfig(cloudflareApplicationAudience, cloudflareTeamDomain, hostnameMatchSettings, pathMatchSettings)
{
    FailedResponseBody = "custom error message/html", // default: string.Empty; response body when JWT validation fails
    FailedResponseStatusCode = 403, // default: 403; response status code when JWT validation fails
    FailedValidationLogLevel = LogLevel.Information, // default: LogLevel.Warning; level used when a request's JWT validation fails
    CanIncludePiiInLogs = false, // default: false; when false, the authenticated user's email is redacted in logs
    KeyRequestTimeout = TimeSpan.FromSeconds(10), // default: 10s; per-request timeout for downloading Cloudflare's signing keys
    AllowedServiceTokenClientIds = new[] { "<service-token-client-id>.access" }, // default: empty; see Service tokens below
};

(...) // other middlewares should go after JWT validation

app.Run();
```

### Pattern matching
`StringMatchSettings` patterns (for hostnames and paths) are matched against the **whole** value:

- A pattern **without** `*` is an exact, whole-value match. `internal.domain.com` matches only that host, not `internal.domain.com.evil.com`; `/admin` matches only `/admin`, not `/administrator`.
- `*` is a wildcard matching any sequence of characters (including an empty one). Use it for prefix/suffix/segment matching:
  - `/admin/*` matches `/admin/` and anything below it (but not the bare `/admin`; use `/admin*` if you also want that).
  - `*.domain.com` matches any subdomain of `domain.com`.
- Matching is case-insensitive.
- Hostname patterns are matched against the host only — any port is ignored (e.g. `internal.domain.com` matches both `internal.domain.com` and `internal.domain.com:5000`). Path patterns are matched against the request path (without the query string).
- `MatchingMode.Include` requires JWT validation only for values that match a pattern; `MatchingMode.Exclude` requires validation for everything **except** values that match. The `IncludeAll` / `ExcludeAll` / `IncludeAllExcept(...)` / `ExcludeAllExcept(...)` helpers cover the common cases. You can also pass raw `Regex` objects, which are used as-is (not anchored for you).

> **Breaking change (v4):** patterns are now anchored at both ends. Previously they were prefix-only (start-anchored), so `/public` also matched `/publicadmin` — which could unintentionally exclude endpoints from validation. If you relied on prefix matching, append a `*` to your patterns (e.g. change `/admin` to `/admin/*` or `/admin*`).

### Service tokens
A request authenticated with a [Cloudflare Access service token](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/) has no user, so it arrives without the `Cf-Access-Authenticated-User-Email` header and its JWT has no `email` claim. With `ValidateAuthenticatedEmail` on (the default), such requests are rejected unless the token's Client ID is listed in `AllowedServiceTokenClientIds`.

- List the full Client ID, the same value sent as `CF-Access-Client-Id`, including its `.access` suffix. Cloudflare puts it in the JWT's `common_name` claim. The Client ID is not a secret; the Client Secret is never needed here.
- The token's signature, issuer and audience are validated exactly as for a user's token. Only the email match is skipped, and only for a token that has no `email` claim.
- An allowed service token is accepted on every hostname and path the middleware validates.
- With `ValidateAuthenticatedEmail` off, the list is not used: any token Cloudflare issued for the application is accepted.

### Logging
The middleware logs through the standard `ILogger` pipeline (category `CloudflareJwtValidator.CloudflareJwtValidationMiddleware`), so logs flow to whatever providers your app has configured and are filtered by your logging configuration's minimum level. What gets logged and at which level:

- **Failed validations** (missing `Cf-Access-Jwt-Assertion`/`Cf-Access-Authenticated-User-Email` header, or an invalid token) are logged at `FailedValidationLogLevel` (default `LogLevel.Warning`, so they're visible under a typical `Information` minimum level). Lower it (e.g. `Debug`) to quiet them, or set `LogLevel.None` to silence them entirely.
- **Signing-key fetch failures** (couldn't reach Cloudflare's `/cdn-cgi/access/certs`) are logged at `Error`.
- **Per-request traces** ("ignoring"/"validated") are logged at `Debug`; enable `Debug` for this category to see them.

By default the authenticated user's email (PII) is redacted as `<redacted>` in log messages. Set `CanIncludePiiInLogs = true` to log the actual email address.

## Limitations
Only a single configuration is supported per application. The middleware stores its `CloudflareJwtValidatorConfig` (and the signing-key cache) statically, so calling `UseCloudflareJwtValidationMiddleware` more than once makes the last configuration win for all requests. Multiple issuers/audiences in the same app are not currently supported.

The visitor IP included in logs is read from proxy headers (`Cf-Connecting-Ip`, `X-Forwarded-For`, `X-Real-IP`), falling back to the connection's remote IP. These headers can be spoofed by clients, so the logged IP is best-effort for diagnostics only and should not be treated as authoritative.

## Bug / improvements
Please submit an issue for any bugs or improvements :) Pull requests also welcomed.
