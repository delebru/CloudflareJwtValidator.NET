using Microsoft.Extensions.DependencyInjection;

namespace CloudflareJwtValidator
{
    public static class CloudflareJwtValidationExtensions
    {
        public static IServiceCollection AddCloudflareJwtValidation(this IServiceCollection services)
        {
            services.AddHttpClient<CloudflareJwtValidationMiddleware>();

            return services;
        }
    }
}
