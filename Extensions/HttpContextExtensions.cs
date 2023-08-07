using Microsoft.AspNetCore.Http;

namespace CloudflareJwtValidator.Extensions
{
    internal static class HttpContextExtensions
    {
        internal static string GetRequestPath(this HttpContext httpContext)
            => GetRequestPath(httpContext.Request);

        private static string GetRequestPath(HttpRequest request)
        {
            var pathBaseString = string.IsNullOrEmpty(request.PathBase)
                ? null
                : $"/{request.PathBase}";

            return $"{request.Scheme}://{request.Host}{pathBaseString}{request.Path}{request.QueryString}";
        }

        internal static string? GetProxiedVisitorIp(this HttpContext httpContext)
        {
            if (httpContext.Request.Headers.TryGetValue("Cf-Connecting-Ip", out var visitorIp) && !string.IsNullOrEmpty(visitorIp))
            {
                return visitorIp.ToString();
            }

            if (httpContext.Request.Headers.TryGetValue("X-Forwarded-For", out visitorIp) && !string.IsNullOrEmpty(visitorIp))
            {
                return visitorIp.ToString();
            }

            if (httpContext.Request.Headers.TryGetValue("X-Real-IP", out visitorIp) && !string.IsNullOrEmpty(visitorIp))
            {
                return visitorIp.ToString();
            }

            return httpContext.Connection.RemoteIpAddress?.ToString();
        }
    }
}
