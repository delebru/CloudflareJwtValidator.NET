using System;
using System.Text.Json.Serialization;

namespace CloudflareJwtValidator.Models
{
    internal class CloudflareJwtKey
    {
        [JsonPropertyName("kid")]
        public string KeyId { get; }

        [JsonPropertyName("kty")]
        public string KeyType { get; }

        [JsonPropertyName("alg")]
        public string Algorithm { get; }

        [JsonPropertyName("use")]
        public string PublicKeyUse { get; }

        [JsonPropertyName("e")]
        public string PublicKeyExponent { get; }

        [JsonPropertyName("n")]
        public string PublicKeyModulus { get; }

        [JsonConstructor]
        public CloudflareJwtKey(string keyId, string keyType, string algorithm, string publicKeyUse, string publicKeyExponent, string publicKeyModulus)
        {
            if (string.IsNullOrWhiteSpace(keyId))
            {
                throw new ArgumentException($"'{nameof(keyId)}' cannot be null or whitespace.", nameof(keyId));
            }

            if (string.IsNullOrWhiteSpace(keyType))
            {
                throw new ArgumentException($"'{nameof(keyType)}' cannot be null or whitespace.", nameof(keyType));
            }

            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentException($"'{nameof(algorithm)}' cannot be null or whitespace.", nameof(algorithm));
            }

            if (string.IsNullOrWhiteSpace(publicKeyUse))
            {
                throw new ArgumentException($"'{nameof(publicKeyUse)}' cannot be null or whitespace.", nameof(publicKeyUse));
            }

            if (string.IsNullOrWhiteSpace(publicKeyExponent))
            {
                throw new ArgumentException($"'{nameof(publicKeyExponent)}' cannot be null or whitespace.", nameof(publicKeyExponent));
            }

            if (string.IsNullOrWhiteSpace(publicKeyModulus))
            {
                throw new ArgumentException($"'{nameof(publicKeyModulus)}' cannot be null or whitespace.", nameof(publicKeyModulus));
            }

            KeyId = keyId;
            KeyType = keyType;
            Algorithm = algorithm;
            PublicKeyUse = publicKeyUse;
            PublicKeyExponent = publicKeyExponent;
            PublicKeyModulus = publicKeyModulus;
        }
    }
}