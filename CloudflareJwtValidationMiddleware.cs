using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using CloudflareJwtValidator.Extensions;
using CloudflareJwtValidator.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace CloudflareJwtValidator
{
    public class CloudflareJwtValidationMiddleware
    {
        private const string kCloudflareJwtHeader = "Cf-Access-Jwt-Assertion";
        private const string kCloudflareEmailHeader = "Cf-Access-Authenticated-User-Email";

        private readonly RequestDelegate _next;
        private readonly ILogger<CloudflareJwtValidationMiddleware> _logger;

        public CloudflareJwtValidationMiddleware(RequestDelegate next, HttpClient httpClient, ILogger<CloudflareJwtValidationMiddleware> logger)
        {
            if (Config is null)
            {
                throw new InvalidOperationException(
                    $"Middleware must be initialized with the provided extension method: " +
                    $"IApplicationBuilder.UseCloudflareJwtValidationMiddleware({nameof(CloudflareJwtValidatorConfig)})"
                );
            }

            if (httpClient is null)
            {
                throw new ArgumentNullException(
                    nameof(httpClient),
                    $"Middleware is missing required services. Add 'builder.Services.AddCloudflareJwtValidation();' to the app's services."
                );
            }

            _next = next;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            HttpClient = httpClient;
        }

        private HttpClient HttpClient { get; }

        internal static CloudflareJwtValidatorConfig Config { get; set; } = default!;

        public async Task Invoke(HttpContext httpContext)
        {
            if (!IsTokenValidationRequired(httpContext.Request.Host, httpContext.Request.Path))
            {
                _logger.LogDebug(
                    "Ignoring JWT. IP: {VisitorIp} | Path: '{RequestPath}'",
                    httpContext.GetProxiedVisitorIp(),
                    httpContext.GetRequestPath()
                );

                await _next(httpContext);
            }
            else if (await HasValidJwtToken(httpContext))
            {
                _logger.LogDebug(
                    "JWT validated. IP: {VisitorIp} | User: {User} | Path: '{RequestPath}'",
                    httpContext.GetProxiedVisitorIp(),
                    Config.CanIncludePiiInLogs ? httpContext.Request.Headers[kCloudflareEmailHeader].ToString() : "<redacted>",
                    httpContext.GetRequestPath()
                );

                await _next(httpContext);
            }
            else
            {
                var response = httpContext.Response;

                response.StatusCode = Config.FailedResponseStatusCode;

                if (response.Body.CanWrite)
                {
                    await response.Body.WriteAsync(Config.FailedResponseBodyData);
                    await response.Body.FlushAsync();
                }
            }
        }

        private static bool IsTokenValidationRequired(HostString hostname, PathString path)
            => Config.HostnameMatchSettings.IsMatch(hostname.ToString()) 
            && Config.PathMatchSettings.IsMatch(path.ToString());

        private async Task<bool> HasValidJwtToken(HttpContext httpContext)
        {
            const string validationErrorMessage = "JWT validation failure:";

            var requestHeaders = httpContext.Request.Headers;

            if (!requestHeaders.TryGetValue(kCloudflareJwtHeader, out var cloudflareJwtValue) || string.IsNullOrWhiteSpace(cloudflareJwtValue))
            {
                _logger.Log(
                    Config.FailedValidationLogLevel,
                    "{Message} missing header value '{Header}'. IP: {VisitorIp} | User: {User} | Path: '{RequestPath}'",
                    validationErrorMessage,
                    kCloudflareJwtHeader,
                    httpContext.GetProxiedVisitorIp(),
                    Config.CanIncludePiiInLogs ? requestHeaders[kCloudflareEmailHeader].ToString() : "<redacted>",
                    httpContext.GetRequestPath()
                );

                return false;
            }

            StringValues authenticatedUserEmail;

            if (Config.ValidateAuthenticatedEmail)
            {
                if (!requestHeaders.TryGetValue(kCloudflareEmailHeader, out authenticatedUserEmail) || string.IsNullOrWhiteSpace(authenticatedUserEmail))
                {
                    _logger.Log(
                        Config.FailedValidationLogLevel,
                        "{Message} missing header value '{Header}'. IP: {VisitorIp} | Path: '{RequestPath}'",
                        validationErrorMessage,
                        kCloudflareEmailHeader,
                        httpContext.GetProxiedVisitorIp(),
                        httpContext.GetRequestPath()
                    );

                    return false;
                }
            }
            else
            {
                authenticatedUserEmail = string.Empty;
            }

            RsaSecurityKey[] cloudflareJwtSigningKeys;

            try
            {
                cloudflareJwtSigningKeys = await LockAndGetCloudflareJwtSigningKeys();
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Cloudflare JWT signing key request failed. IP: {VisitorIp} | Path: '{RequestPath}'",
                    httpContext.GetProxiedVisitorIp(),
                    httpContext.GetRequestPath()
                );

                return false;
            }

            var tokenValidationResult = await ValidateJwtToken(cloudflareJwtValue.ToString(), cloudflareJwtSigningKeys, authenticatedUserEmail.ToString());

            // An unrecognised key ID usually means Cloudflare rotated its signing keys since our last
            // fetch. Force a (rate-limited) key refresh and retry validation once before giving up.
            if (!tokenValidationResult.IsValid
                && tokenValidationResult.Exception is SecurityTokenSignatureKeyNotFoundException)
            {
                RsaSecurityKey[] refreshedSigningKeys;

                try
                {
                    refreshedSigningKeys = await LockAndGetCloudflareJwtSigningKeys(forceRefresh: true);
                }
                catch (Exception ex)
                {
                    _logger.LogError(
                        ex,
                        "Cloudflare JWT signing key request failed. IP: {VisitorIp} | Path: '{RequestPath}'",
                        httpContext.GetProxiedVisitorIp(),
                        httpContext.GetRequestPath()
                    );

                    return false;
                }

                // Only retry if the refresh actually produced new keys (it may have been rate-limited).
                if (!ReferenceEquals(refreshedSigningKeys, cloudflareJwtSigningKeys))
                {
                    tokenValidationResult = await ValidateJwtToken(cloudflareJwtValue.ToString(), refreshedSigningKeys, authenticatedUserEmail.ToString());
                }
            }

            if (!tokenValidationResult.IsValid)
            {
                _logger.Log(
                    Config.FailedValidationLogLevel,
                    tokenValidationResult.Exception,
                    "{Message} invalid token. IP: {VisitorIp} | User: {User} | Path: '{RequestPath}'",
                    validationErrorMessage,
                    httpContext.GetProxiedVisitorIp(),
                    Config.CanIncludePiiInLogs ? requestHeaders[kCloudflareEmailHeader].ToString() : "<redacted>",
                    httpContext.GetRequestPath()
                );
            }

            return tokenValidationResult.IsValid;
        }

        private static SemaphoreSlim CloudflareJwtKeysCacheSemaphore { get; } = new SemaphoreSlim(1, 1);

        // Ensure thread safety and a single instance of GetCloudflareJwtSigningKeys function execution
        private async Task<RsaSecurityKey[]> LockAndGetCloudflareJwtSigningKeys(bool forceRefresh = false)
        {
            await CloudflareJwtKeysCacheSemaphore.WaitAsync();

            try
            {
                return await GetCloudflareJwtSigningKeys(forceRefresh);
            }
            finally
            {
                CloudflareJwtKeysCacheSemaphore.Release();
            }
        }

        private static (RsaSecurityKey[]?, DateTime) CloudflareJwtKeysCache { get; set; }
        
        private async Task<RsaSecurityKey[]> GetCloudflareJwtSigningKeys(bool forceRefresh = false)
        {
            var (cachedSigningKeys, cacheDate) = CloudflareJwtKeysCache;

            if (cachedSigningKeys != null)
            {
                var isCacheExpired = cacheDate + Config.KeyCacheTime < DateTime.UtcNow;

                // A forced refresh (triggered by an unknown key ID) is rate-limited to avoid spamming
                // Cloudflare when many tokens with unrecognised key IDs are received.
                var isForcedRefreshAllowed = forceRefresh
                    && cacheDate + Config.MinKeyRefreshInterval < DateTime.UtcNow;

                if (!isCacheExpired && !isForcedRefreshAllowed)
                {
                    return cachedSigningKeys;
                }
            }

            var url = $"{Config.JwtIssuer}/cdn-cgi/access/certs";

            var cloudflareJwtResponseJson = await HttpClient.GetStringAsync(url);

            var cloudflareJwtResponse = JsonSerializer.Deserialize<CloudflareJwtResponse>(cloudflareJwtResponseJson)
                ?? throw new NullReferenceException(nameof(CloudflareJwtResponse));

            var signingKeys = cloudflareJwtResponse.PublicCertificates.ToSigningKeys();

            CloudflareJwtKeysCache = (signingKeys, DateTime.UtcNow);

            return signingKeys;
        }

        private static async Task<TokenValidationResult> ValidateJwtToken(string cloudflareJwtValue, RsaSecurityKey[] cloudflareJwtSigningKeys, string authenticatedUserEmail)
        {
            var tokenHandler = new JwtSecurityTokenHandler()
            {
                // Keep the original JWT claim names (e.g. 'email') instead of mapping them to WS-* URIs.
                MapInboundClaims = false
            };

            var validationParameters = new TokenValidationParameters()
            {
                ValidIssuer = Config.JwtIssuer,
                ValidAudience = Config.AppAud,
                IssuerSigningKeys = cloudflareJwtSigningKeys,
                ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
                LogTokenId = false,
                ValidateIssuerSigningKey = true
            };

            // ValidateTokenAsync parses the token once, selects the signing key by its 'kid' header,
            // and returns an invalid result (rather than throwing) for malformed or unverifiable tokens.
            var tokenValidationResult = await tokenHandler.ValidateTokenAsync(cloudflareJwtValue, validationParameters);

            if (tokenValidationResult.IsValid && Config.ValidateAuthenticatedEmail)
            {
                var tokenUserEmail = tokenValidationResult.ClaimsIdentity?.FindFirst("email")?.Value;

                if (tokenUserEmail is null
                    || !authenticatedUserEmail.Equals(tokenUserEmail, StringComparison.OrdinalIgnoreCase))
                {
                    var loggedTokenEmail = Config.CanIncludePiiInLogs ? tokenUserEmail : "<redacted>";
                    var loggedHeaderEmail = Config.CanIncludePiiInLogs ? authenticatedUserEmail : "<redacted>";

                    return new TokenValidationResult()
                    {
                        IsValid = false,
                        Exception = new Exception($"email address missmatch. Token's user email: {loggedTokenEmail} / CF header's user email: {loggedHeaderEmail}")
                    };
                }
            }

            return tokenValidationResult;
        }
    }
}