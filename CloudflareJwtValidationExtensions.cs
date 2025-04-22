using Microsoft.Extensions.DependencyInjection;

namespace CloudflareJwtValidator
{
    public static class CloudflareJwtValidationExtensions
    {
        public static IServiceCollection AddCloudflareJwtValidation(IServiceCollection services)
        {
            services.AddHttpClient<CloudflareJwtValidationMiddleware>();

            return services;
        }
    }
}
