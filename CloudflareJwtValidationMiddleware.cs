﻿using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using CloudflareJwtValidator.Extensions;
using CloudflareJwtValidator.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace CloudflareJwtValidator
{
    public class CloudflareJwtValidationMiddleware
    {
        private const string kCloudflareJwtHeader = "Cf-Access-Jwt-Assertion";
        private const string kCloudflareEmailHeader = "Cf-Access-Authenticated-User-Email";

        private const string kLogTag = "[CloudflareJwtValidator]";

        private readonly RequestDelegate _next;

        public CloudflareJwtValidationMiddleware(RequestDelegate next, HttpClient httpClient)
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
            HttpClient = httpClient;
        }

        private HttpClient HttpClient { get; }

        internal static CloudflareJwtValidatorConfig Config { get; set; } = default!;

        private static void Log(string v) 
            => Console.WriteLine($"{kLogTag} {v}");

        public async Task Invoke(HttpContext httpContext)
        {
            if (!IsTokenValidationRequired(httpContext.Request.Host, httpContext.Request.Path))
            {
                if (Config.UseDebugLogs)
                {
                    Log(
                        $"[Ignoring JWT]" +
                        $" IP: {httpContext.GetProxiedVisitorIp()}" +
                        $" | Path: '{httpContext.GetRequestPath()}'"
                    );
                }

                await _next(httpContext);
            }
            else if (await HasValidJwtToken(httpContext.Request.Headers))
            {
                if (Config.UseDebugLogs)
                {
                    Log(
                        $"[JWT Validated]" +
                        $" IP: {httpContext.GetProxiedVisitorIp()}" +
                        $" | User: {httpContext.Request.Headers[kCloudflareEmailHeader]}" +
                        $" | Path: '{httpContext.GetRequestPath()}'"
                    );
                }

                await _next(httpContext);
            }
            else
            {
                var response = httpContext.Response;

                response.StatusCode = Config.FailedResponseStatusCode;

                if (Config.LogFailedValidations)
                {
                    Log(
                        $"[JWT Failed Validation]" +
                        $" IP: {httpContext.GetProxiedVisitorIp()}" +
                        $" | User: {httpContext.Request.Headers[kCloudflareEmailHeader]}" +
                        $" | Path: '{httpContext.GetRequestPath()}'"
                    );
                }

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

        private async Task<bool> HasValidJwtToken(IHeaderDictionary requestHeaders)
        {
            const string validationErrorMessage = "JWT validation failure:";

            if (!requestHeaders.TryGetValue(kCloudflareJwtHeader, out var cloudflareJwtValue) || string.IsNullOrWhiteSpace(cloudflareJwtValue))
            {
                if (Config.LogFailedValidations)
                {
                    Log($"{validationErrorMessage} missing header value '{kCloudflareJwtHeader}'");
                }

                return false;
            }

            StringValues authenticatedUserEmail;

            if (Config.ValidateAuthenticatedEmail)
            {
                if (!requestHeaders.TryGetValue(kCloudflareEmailHeader, out authenticatedUserEmail) || string.IsNullOrWhiteSpace(authenticatedUserEmail))
                {
                    if (Config.LogFailedValidations)
                    {
                        Log($"{validationErrorMessage} missing header value '{kCloudflareEmailHeader}'");
                    }

                    return false;
                }
            }
            else
            {
                authenticatedUserEmail = string.Empty;
            }

            JwtSigningKey[] cloudflareJwtSigningKeys;

            try
            {
                cloudflareJwtSigningKeys = await LockAndGetCloudflareJwtSigningKeys();
            }
            catch (Exception ex)
            {
                if (Config.LogFailedValidations)
                {
                    Log($"Cloudflare JWT request failure: {(Config.UseDebugLogs ? ex.ToString() : ex.Message)}");
                }

                return false;
            }

            var tokenValidationResult = await ValidateJwtToken(cloudflareJwtValue.ToString(), cloudflareJwtSigningKeys, authenticatedUserEmail.ToString());
            
            if (!tokenValidationResult.IsValid && Config.LogFailedValidations)
            {
                var errorLog = Config.UseDebugLogs 
                    ? tokenValidationResult.Exception.ToString()
                    : tokenValidationResult.Exception.Message;

                Log($"{validationErrorMessage} invalid token: {errorLog}");
            }

            return tokenValidationResult.IsValid;
        }

        private static SemaphoreSlim CloudflareJwtKeysCacheSemaphore { get; } = new SemaphoreSlim(1, 1);

        // Ensure thread safety and a single instance of GetCloudflareJwtSigningKeys function execution
        private async Task<JwtSigningKey[]> LockAndGetCloudflareJwtSigningKeys()
        {
            await CloudflareJwtKeysCacheSemaphore.WaitAsync();

            try
            {
                return await GetCloudflareJwtSigningKeys();
            }
            finally
            {
                CloudflareJwtKeysCacheSemaphore.Release();
            }
        }

        private static (JwtSigningKey[]?, DateTime) CloudflareJwtKeysCache { get; set; }
        
        private async Task<JwtSigningKey[]> GetCloudflareJwtSigningKeys()
        {
            var cloudflareJwtSigningKeys = CloudflareJwtKeysCache.Item1;
            var cloudflareJwtResponseCacheDate = CloudflareJwtKeysCache.Item2;

            if (cloudflareJwtSigningKeys is null || cloudflareJwtResponseCacheDate + Config.KeyCacheTime < DateTime.UtcNow)
            {
                var url = $"{Config.JwtIssuer}/cdn-cgi/access/certs";

                var cloudflareJwtResponseJson = await HttpClient.GetStringAsync(url);

                var cloudflareJwtResponse = JsonSerializer.Deserialize<CloudflareJwtResponse>(cloudflareJwtResponseJson)
                    ?? throw new NullReferenceException(nameof(CloudflareJwtResponse));

                cloudflareJwtSigningKeys = cloudflareJwtResponse.PublicCertificates.ToSigningKeys();

                CloudflareJwtKeysCache = (cloudflareJwtSigningKeys, DateTime.UtcNow);
            }

            return cloudflareJwtSigningKeys;
        }

        private static async Task<TokenValidationResult> ValidateJwtToken(string cloudflareJwtValue, JwtSigningKey[] cloudflareJwtSigningKeys, string authenticatedUserEmail)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.ReadJwtToken(cloudflareJwtValue);

            if (!token.Header.TryGetValue("kid", out var keyIdObj))
            {
                return new TokenValidationResult()
                {
                    IsValid = false,
                    Exception = new Exception($"decoded token doesn't contain 'kid' header.")
                };
            }

            var keyId = keyIdObj.ToString();

            if (string.IsNullOrWhiteSpace(keyId))
            {
                return new TokenValidationResult()
                {
                    IsValid = false,
                    Exception = new Exception($"decoded token contains a null or empty key ID.")
                };
            }

            var cloudflareJwtSigningKey = cloudflareJwtSigningKeys
                .FirstOrDefault(x => x.KeyId == keyId);

            if (cloudflareJwtSigningKey is null)
            {
                return new TokenValidationResult()
                {
                    IsValid = false,
                    Exception = new Exception($"can't find matching signing key with ID {keyId}")
                };
            }

            if (Config.ValidateAuthenticatedEmail
                && (!token.Payload.TryGetValue("email", out var tokenUserEmail) 
                    || !authenticatedUserEmail.Equals(tokenUserEmail.ToString(), StringComparison.OrdinalIgnoreCase)))
            {
                return new TokenValidationResult()
                {
                    IsValid = false,
                    Exception = new Exception($"email address missmatch. Token's user email: {tokenUserEmail} / CF header's user email: {authenticatedUserEmail}")
                };
            }

            var validationParameters = new TokenValidationParameters()
            {
                ValidIssuer = Config.JwtIssuer,
                ValidAudience = Config.AppAud,
                IssuerSigningKey = cloudflareJwtSigningKey.SigningKey,
                LogTokenId = false,
                ValidateIssuerSigningKey = true
            };

            return await tokenHandler.ValidateTokenAsync(cloudflareJwtValue, validationParameters);
        }
    }
}