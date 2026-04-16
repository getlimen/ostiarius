using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Ostiarius.Application.Common.Interfaces;
using Ostiarius.Infrastructure.Control;

namespace Ostiarius.Infrastructure.Proxy;

public sealed class AuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IRouteStore _routes;
    private readonly IJwtVerifier _verifier;
    private readonly IRevokedTokenCache _revoked;
    private readonly OstiariusControlOptions _options;
    private readonly ILogger<AuthMiddleware> _log;

    public AuthMiddleware(
        RequestDelegate next,
        IRouteStore routes,
        IJwtVerifier verifier,
        IRevokedTokenCache revoked,
        IOptions<OstiariusControlOptions> options,
        ILogger<AuthMiddleware> log)
    {
        _next = next;
        _routes = routes;
        _verifier = verifier;
        _revoked = revoked;
        _options = options.Value;
        _log = log;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        ctx.Request.Headers.Remove("X-Limen-User-Id");
        ctx.Request.Headers.Remove("X-Limen-User-Email");
        ctx.Request.Headers.Remove("X-Limen-Auth-Method");
        ctx.Request.Headers.Remove("X-Limen-Resource-Id");

        if (ctx.Request.Path == "/healthz")
        {
            await _next(ctx);
            return;
        }

        var host = ctx.Request.Host.Host;
        var route = _routes.Snapshot().FirstOrDefault(r =>
            string.Equals(r.Hostname, host, StringComparison.OrdinalIgnoreCase));

        if (route is null)
        {
            await _next(ctx);
            return;
        }

        if (string.Equals(route.AuthPolicy, "none", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(route.AuthPolicy))
        {
            await _next(ctx);
            return;
        }

        var cookie = ctx.Request.Cookies["limen_session"];
        if (string.IsNullOrEmpty(cookie))
        {
            Redirect(ctx, route);
            return;
        }

        if (!_verifier.TryVerify(cookie, out var claims) || claims is null)
        {
            Redirect(ctx, route);
            return;
        }

        if (claims.RouteId != route.RouteId)
        {
            _log.LogDebug("Cookie routeId {Cookie} does not match host route {Host}", claims.RouteId, route.RouteId);
            Redirect(ctx, route);
            return;
        }

        if (claims.ExpiresAtUnix < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            Redirect(ctx, route);
            return;
        }

        if (_revoked.IsRevoked(claims.Jti))
        {
            Redirect(ctx, route);
            return;
        }

        ctx.Request.Headers["X-Limen-User-Id"] = claims.Subject;
        ctx.Request.Headers["X-Limen-User-Email"] = claims.Subject;
        ctx.Request.Headers["X-Limen-Auth-Method"] = claims.AuthMethod;
        ctx.Request.Headers["X-Limen-Resource-Id"] = claims.RouteId.ToString();

        await _next(ctx);
    }

    private void Redirect(HttpContext ctx, Limen.Contracts.ProxyMessages.RouteSpec route)
    {
        if (string.IsNullOrWhiteSpace(_options.LimenPublicUrl))
        {
            _log.LogWarning("LimenPublicUrl not configured; cannot redirect anonymous request to login");
            ctx.Response.StatusCode = 401;
            return;
        }

        var returnTo = $"{ctx.Request.Scheme}://{ctx.Request.Host}{ctx.Request.Path}{ctx.Request.QueryString}";
        var loginUrl = $"{_options.LimenPublicUrl.TrimEnd('/')}/auth/login?routeId={route.RouteId}&returnTo={Uri.EscapeDataString(returnTo)}";
        ctx.Response.Redirect(loginUrl);
    }
}
