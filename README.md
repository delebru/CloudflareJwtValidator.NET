# Cloudflare JWT Validator

[![Nuget](https://img.shields.io/nuget/v/CloudflareJwtValidator.svg)](https://www.nuget.org/packages/CloudflareJwtValidator)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-yellow.svg)](https://opensource.org/license/gpl-3-0)
[![Build](https://github.com/delebru/CloudflareJwtValidator.NET/actions/workflows/build.yml/badge.svg)](https://github.com/delebru/CloudflareJwtValidator.NET/actions/workflows/build.yml)

Middleware for simple JWT (JSON Web Token) validation on web apps behind Cloudflare Zero Trust. This middleware will ensure requests to the web app are sent by Cloudflare by validating the token signature under the `Cf-Access-Jwt-Assertion` header, and ensure the `Cf-Access-Authenticated-User-Email` user email matches the token's user email. 

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


In the example below, the middleware will ignore JWT headers on all requests when the request hostname is `internal.domain.com`, and will also only check for valid JWT headers if the path is `/admin/*` (`*` being a wildcard).

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
    LogFailedValidations = true, // default: true; enables logging when a request's JWT validation fails
    FailedResponseBody = "custom error message/html", // default: string.Empty; response body when JWT validation fails
    FailedResponseStatusCode = 403, // default: 403; response status code when JWT validation fails
    UseDebugLogs = false, // default: false; logs all requests and validation result
};

(...) // other middlewares should go after JWT validation

app.Run();
```

## Bug / improvements
Please submit an issue for any bugs or improvements :) Pull requests also welcomed.
