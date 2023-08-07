using CloudflareJwtValidator.Models;
using Microsoft.AspNetCore.Builder;

namespace CloudflareJwtValidator.Extensions
{
    public static class CloudflareJwtValidationMiddlewareExtensions
    {
        public static IApplicationBuilder UseCloudflareJwtValidationMiddleware(this IApplicationBuilder builder, CloudflareJwtValidatorConfig config)
        {
            CloudflareJwtValidationMiddleware.Config = config;

            return builder.UseMiddleware<CloudflareJwtValidationMiddleware>();
        }
    }
}