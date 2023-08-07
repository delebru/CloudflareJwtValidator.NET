using System;
using System.Text.Json.Serialization;

namespace CloudflareJwtValidator.Models
{
    internal class CloudflareJwtCertificate
    {
        [JsonPropertyName("kid")]
        public string KeyId { get; }

        [JsonPropertyName("cert")]
        public string Certificate { get; }

        [JsonConstructor]
        public CloudflareJwtCertificate(string keyId, string certificate)
        {
            if (string.IsNullOrWhiteSpace(keyId))
            {
                throw new ArgumentException($"'{nameof(keyId)}' cannot be null or whitespace.", nameof(keyId));
            }

            if (string.IsNullOrWhiteSpace(certificate))
            {
                throw new ArgumentException($"'{nameof(certificate)}' cannot be null or whitespace.", nameof(certificate));
            }

            KeyId = keyId;
            Certificate = certificate;
        }
    }
}