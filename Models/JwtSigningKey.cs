using Microsoft.IdentityModel.Tokens;

namespace CloudflareJwtValidator.Models
{
    internal class JwtSigningKey
    {
        public string KeyId { get; }
        
        public X509SecurityKey SigningKey { get; }

        public JwtSigningKey(string keyId, X509SecurityKey signingKey)
        {
            if (string.IsNullOrWhiteSpace(keyId))
            {
                throw new System.ArgumentException($"'{nameof(keyId)}' cannot be null or whitespace.", nameof(keyId));
            }

            KeyId = keyId;
            SigningKey = signingKey;
        }
    }
}