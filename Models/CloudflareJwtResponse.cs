using System;
using System.Text.Json.Serialization;

namespace CloudflareJwtValidator.Models
{
    internal class CloudflareJwtResponse
    {
        [JsonPropertyName("keys")]
        public CloudflareJwtKey[] Keys { get; }

        [JsonPropertyName("public_cert")]
        public CloudflareJwtCertificate PublicCertificate { get; }

        [JsonPropertyName("public_certs")]
        public CloudflareJwtCertificate[] PublicCertificates { get; }

        [JsonConstructor]
        public CloudflareJwtResponse(CloudflareJwtKey[] keys, CloudflareJwtCertificate publicCertificate, CloudflareJwtCertificate[] publicCertificates)
        {
            Keys = keys ?? throw new ArgumentNullException(nameof(keys));
            PublicCertificate = publicCertificate ?? throw new ArgumentNullException(nameof(publicCertificate));
            PublicCertificates = publicCertificates ?? throw new ArgumentNullException(nameof(publicCertificates));
        }
    }
}