using System;
using System.Text;

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
        /// Enables debug logs which will log all requests and full exceptions on failed JWT validations. 
        /// Forces LogFailedValidations to return true.
        /// </summary>
        public bool UseDebugLogs { get; set; }

        /// <summary>
        /// How long to cache keys from Cloudflare and avoid spammy web requests. 
        /// See: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/
        /// 'By default, the Access rotates the signing key every 6 weeks. This means you will need to programmatically 
        /// or manually update your keys as they rotate. Previous keys remain valid for 7 days after rotation to allow 
        /// time for you to make the update.'
        /// </summary>
        public TimeSpan KeyCacheTime { get; set; } = TimeSpan.FromHours(12);

        private bool _logFailedValidations = true;
        /// <summary>
        /// Enables logging for failed JWT validations. Includes exception messages, if you need full strings set 
        /// UseDebugLogs to true.
        /// </summary>
        public bool LogFailedValidations {
            get => _logFailedValidations || UseDebugLogs;
            set => _logFailedValidations = value;
        }
    }
}