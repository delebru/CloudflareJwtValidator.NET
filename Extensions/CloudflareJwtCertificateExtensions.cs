using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Microsoft.IdentityModel.Tokens;

using CloudflareJwtValidator.Models;

namespace CloudflareJwtValidator.Extensions
{
    internal static class CloudflareJwtCertificateExtensions
    {
        public static RsaSecurityKey[] ToSigningKeys(this CloudflareJwtCertificate[] cloudflareJwtCertificates)
            => cloudflareJwtCertificates
                .Select(cert => cert.ToSigningKey())
                .ToArray();

        public static RsaSecurityKey ToSigningKey(this CloudflareJwtCertificate cloudflareJwtCertificate)
        {
            var cleanedCertificateString = cloudflareJwtCertificate.Certificate
                .Replace("-----BEGIN CERTIFICATE-----", null)
                .Replace("-----END CERTIFICATE-----", null);

            var certificateData = Convert.FromBase64String(cleanedCertificateString);

            using var certificate = new X509Certificate2(certificateData);

            using var rsa = certificate.GetRSAPublicKey()
                ?? throw new InvalidOperationException("Cloudflare signing certificate does not contain an RSA public key.");

            return new RsaSecurityKey(rsa.ExportParameters(false));
        }
    }
}
