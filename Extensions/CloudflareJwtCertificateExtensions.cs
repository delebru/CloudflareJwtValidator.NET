using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Microsoft.IdentityModel.Tokens;

using CloudflareJwtValidator.Models;

namespace CloudflareJwtValidator.Extensions
{
    internal static class CloudflareJwtCertificateExtensions
    {
        public static JwtSigningKey[] ToSigningKeys(this CloudflareJwtCertificate[] cloudflareJwtCertificates)
            => cloudflareJwtCertificates
                .Select(cert => cert.ToSigningKey())
                .ToArray();

        public static JwtSigningKey ToSigningKey(this CloudflareJwtCertificate cloudflareJwtCertificate)
        {
            var cleanedCertificateString = cloudflareJwtCertificate.Certificate
                .Replace("-----BEGIN CERTIFICATE-----", null)
                .Replace("-----END CERTIFICATE-----", null);

            var certificateData = Convert.FromBase64String(cleanedCertificateString);

            var certificate = new X509Certificate2(certificateData);

            var signingKey = new X509SecurityKey(certificate);

            return new JwtSigningKey(cloudflareJwtCertificate.KeyId, signingKey);
        }
    }
}
