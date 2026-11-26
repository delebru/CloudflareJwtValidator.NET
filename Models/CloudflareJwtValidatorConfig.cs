using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

using Microsoft.Extensions.Logging;

namespace CloudflareJwtValidator.Models
{
    public class CloudflareJwtValidatorConfig
    {
        public CloudflareJwtValidatorConfig(
            string appAud,
            string jwtIssuer,
            StringMatchSettings hostnameMatchSettings,
            StringMatchSettings pathMatchSettings)
        {
            if (string.IsNullOrWhiteSpace(appAud))
            {
                throw new ArgumentException($"'{nameof(appAud)}' cannot be null or whitespace.", nameof(appAud));
            }

            if (string.IsNullOrWhiteSpace(jwtIssuer))
            {
                throw new ArgumentException($"'{nameof(jwtIssuer)}' cannot be null or whitespace.", nameof(jwtIssuer));
            }

            if (!jwtIssuer.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException($"'{nameof(jwtIssuer)}' must start with https://. IE: 'https://<team-domain>.cloudflareaccess.com'", nameof(jwtIssuer));
            }

            AppAud = appAud;
            JwtIssuer = jwtIssuer;
            HostnameMatchSettings = hostnameMatchSettings;
            PathMatchSettings = pathMatchSettings;
        }


        public CloudflareJwtValidatorConfig(string appAud, string jwtIssuer)
            : this(appAud, jwtIssuer, hostnameMatchSettings: StringMatchSettings.IncludeAll, pathMatchSettings: StringMatchSettings.IncludeAll) { }


        public CloudflareJwtValidatorConfig(string appAud, string jwtIssuer, StringMatchSettings hostnameMatchSettings)
            : this(appAud, jwtIssuer, hostnameMatchSettings, pathMatchSettings: StringMatchSettings.IncludeAll) { }


        /// <summary>
        /// Cloudflare's APP AUD tag: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/#get-your-aud-tag
        /// </summary>
        public string AppAud { get; }

        /// <summary>
        /// Full issuer scheme and hostname, IE: 'https://<team-domain>.cloudflareaccess.com'.
        /// Will be used to validate JWT and retreive the signing keys from https://<team-domain>.cloudflareaccess.com/cdn-cgi/access/certs
        /// </summary>
        public string JwtIssuer { get; }

        /// <summary>
        /// Allows to filter which hostnames the app will enforce JWT validation.
        /// </summary>
        public StringMatchSettings HostnameMatchSettings { get; }

        /// <summary>
        /// Allows to filter which paths the app will enforce JWT validation.
        /// </summary>
        public StringMatchSettings PathMatchSettings { get; }

        /// <summary>
        /// Whenever the JWT validation fails, the app will respond with the specified body string.
        /// </summary>
        public string FailedResponseBody
        {
            get => Encoding.UTF8.GetString(FailedResponseBodyData);
            set => FailedResponseBodyData = Encoding.UTF8.GetBytes(value);
        }

        internal byte[] FailedResponseBodyData { get; set; } = Encoding.UTF8.GetBytes(string.Empty);

        /// <summary>
        /// Whenever the JWT validation fails, the app will use this status code for the response.
        /// </summary>
        public int FailedResponseStatusCode { get; set; } = 403;

        /// <summary>
        /// Defines the log level for when JWT validation fails.
        /// </summary>
        public LogLevel FailedValidationLogLevel { get; set; } = LogLevel.Warning;

        /// <summary>
        /// Defines if the app can include PII (Personally Identifiable Information) in logs, such as the JWT's payload email address.
        /// </summary>
        public bool CanIncludePiiInLogs { get; set; }

        /// <summary>
        /// How long to cache keys from Cloudflare and avoid spammy web requests. 
        /// See: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/
        /// 'By default, the Access rotates the signing key every 6 weeks. This means you will need to programmatically 
        /// or manually update your keys as they rotate. Previous keys remain valid for 7 days after rotation to allow 
        /// time for you to make the update.'
        /// </summary>
        public TimeSpan KeyCacheTime { get; set; } = TimeSpan.FromHours(12);

        /// <summary>
        /// Maximum time to wait for the request that downloads Cloudflare's signing keys from
        /// {JwtIssuer}/cdn-cgi/access/certs. This is applied per request (via a CancellationToken), so it
        /// does not affect the shared HttpClient's global timeout. Because the key request runs under a
        /// lock, keeping this reasonably short prevents a slow response from stalling other requests.
        /// Must be a finite, positive duration.
        /// </summary>
        public TimeSpan KeyRequestTimeout
        {
            get => _keyRequestTimeout;
            set
            {
                if (value <= TimeSpan.Zero || value == Timeout.InfiniteTimeSpan)
                {
                    throw new ArgumentOutOfRangeException(nameof(KeyRequestTimeout), value, $"'{nameof(KeyRequestTimeout)}' must be a finite, positive duration.");
                }

                _keyRequestTimeout = value;
            }
        }
        private TimeSpan _keyRequestTimeout = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Minimum time between forced signing-key refreshes triggered by an unrecognised key ID (kid),
        /// e.g. right after Cloudflare rotates its signing keys. When a token's kid is not found in the
        /// cached keys, the keys are refreshed (bypassing <see cref="KeyCacheTime"/>) and validation is
        /// retried once. This interval rate-limits those refreshes so a flood of tokens with unknown key
        /// IDs cannot spam Cloudflare. Should be shorter than <see cref="KeyCacheTime"/> to be effective.
        /// </summary>
        public TimeSpan MinKeyRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Ensures the email address in the Cf-Access-Authenticated-User-Email header matches the JWT's payload email address.
        /// </summary>
        public bool ValidateAuthenticatedEmail { get; set; } = true;

        /// <summary>
        /// Client IDs (the CF-Access-Client-Id value, including its '.access' suffix) of the Cloudflare Access
        /// service tokens allowed through while <see cref="ValidateAuthenticatedEmail"/> is on.
        /// A service token has no user, so its JWT has no email to validate: it carries the Client ID in
        /// the 'common_name' claim instead. Empty by default, which rejects every service token.
        /// See: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/
        /// </summary>
        public IReadOnlyCollection<string> AllowedServiceTokenClientIds { get; set; } = Array.Empty<string>();

        [Obsolete("Deprecated since 4.0.0, please use FailedValidationLogLevel instead")]
        public bool UseDebugLogs { get; set; }

        [Obsolete("Deprecated since 4.0.0, please use FailedValidationLogLevel instead")]
        public bool LogFailedValidations { get; set; }
    }
}