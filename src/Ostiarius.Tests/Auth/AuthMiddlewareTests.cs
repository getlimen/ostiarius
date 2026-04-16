using FluentAssertions;
using Limen.Contracts.ProxyMessages;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Ostiarius.Application.Common.Interfaces;
using Ostiarius.Infrastructure.Control;
using Ostiarius.Infrastructure.Proxy;
using Xunit;

namespace Ostiarius.Tests.Auth;

public sealed class AuthMiddlewareTests
{
    private const string LimenPublicUrl = "https://limen.example.com";

    private static AuthMiddleware CreateMiddleware(
        RequestDelegate next,
        IRouteStore routes,
        IJwtVerifier verifier,
        IRevokedTokenCache revoked,
        string limenPublicUrl = LimenPublicUrl)
    {
        var options = Options.Create(new OstiariusControlOptions
        {
            LimenPublicUrl = limenPublicUrl
        });
        return new AuthMiddleware(next, routes, verifier, revoked, options, NullLogger<AuthMiddleware>.Instance);
    }

    private static RouteSpec MakeRoute(string hostname, string authPolicy, Guid? routeId = null)
    {
        return new RouteSpec(routeId ?? Guid.NewGuid(), hostname, "http://upstream", true, authPolicy);
    }

    private static DefaultHttpContext MakeContext(string host, string? cookieValue = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Host = new HostString(host);
        ctx.Request.Scheme = "https";
        ctx.Request.Path = "/app";

        if (cookieValue is not null)
        {
            ctx.Request.Headers.Cookie = $"limen_session={cookieValue}";
        }

        return ctx;
    }

    [Fact]
    public async Task NoMatchingRoute_CallsNext()
    {
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(Array.Empty<RouteSpec>());

        var verifier = Substitute.For<IJwtVerifier>();
        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("unknown.example.com");

        await middleware.InvokeAsync(ctx);

        nextCalled.Should().BeTrue();
        ctx.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task RouteAuthPolicyNone_CallsNext_AndStripsHeaders()
    {
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var route = MakeRoute("app.example.com", "none");
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var verifier = Substitute.For<IJwtVerifier>();
        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("app.example.com");
        ctx.Request.Headers["X-Limen-User-Id"] = "spoofed-user";

        await middleware.InvokeAsync(ctx);

        nextCalled.Should().BeTrue();
        ctx.Request.Headers.ContainsKey("X-Limen-User-Id").Should().BeFalse();
    }

    [Fact]
    public async Task RouteAuthPolicyEmpty_CallsNext()
    {
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var route = MakeRoute("app.example.com", "");
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var verifier = Substitute.For<IJwtVerifier>();
        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("app.example.com");

        await middleware.InvokeAsync(ctx);

        nextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task NoCookie_Redirects()
    {
        RequestDelegate next = _ => Task.CompletedTask;

        var route = MakeRoute("app.example.com", "jwt");
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var verifier = Substitute.For<IJwtVerifier>();
        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("app.example.com");

        await middleware.InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(302);
        ctx.Response.Headers.Location.ToString().Should().Contain("/auth/login");
        ctx.Response.Headers.Location.ToString().Should().Contain(route.RouteId.ToString());
    }

    [Fact]
    public async Task InvalidCookie_Redirects()
    {
        RequestDelegate next = _ => Task.CompletedTask;

        var route = MakeRoute("app.example.com", "jwt");
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var verifier = Substitute.For<IJwtVerifier>();
        JwtClaims? nullClaims = null;
        verifier.TryVerify("bad-token", out nullClaims).Returns(x =>
        {
            x[1] = null;
            return false;
        });

        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("app.example.com", "bad-token");

        await middleware.InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(302);
    }

    [Fact]
    public async Task WrongRouteId_Redirects()
    {
        RequestDelegate next = _ => Task.CompletedTask;

        var routeId = Guid.NewGuid();
        var route = MakeRoute("app.example.com", "jwt", routeId);
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var claims = new JwtClaims(Guid.NewGuid(), "user@test.com", Guid.NewGuid(), "password", "route",
            DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());

        var verifier = Substitute.For<IJwtVerifier>();
        verifier.TryVerify("some-token", out Arg.Any<JwtClaims?>()).Returns(x =>
        {
            x[1] = claims;
            return true;
        });

        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("app.example.com", "some-token");

        await middleware.InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(302);
    }

    [Fact]
    public async Task ExpiredClaims_Redirects()
    {
        RequestDelegate next = _ => Task.CompletedTask;

        var routeId = Guid.NewGuid();
        var route = MakeRoute("app.example.com", "jwt", routeId);
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var claims = new JwtClaims(Guid.NewGuid(), "user@test.com", routeId, "password", "route",
            DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds()); // expired

        var verifier = Substitute.For<IJwtVerifier>();
        verifier.TryVerify("some-token", out Arg.Any<JwtClaims?>()).Returns(x =>
        {
            x[1] = claims;
            return true;
        });

        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("app.example.com", "some-token");

        await middleware.InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(302);
    }

    [Fact]
    public async Task RevokedJti_Redirects()
    {
        RequestDelegate next = _ => Task.CompletedTask;

        var routeId = Guid.NewGuid();
        var jti = Guid.NewGuid();
        var route = MakeRoute("app.example.com", "jwt", routeId);
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var claims = new JwtClaims(jti, "user@test.com", routeId, "password", "route",
            DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());

        var verifier = Substitute.For<IJwtVerifier>();
        verifier.TryVerify("some-token", out Arg.Any<JwtClaims?>()).Returns(x =>
        {
            x[1] = claims;
            return true;
        });

        var revoked = Substitute.For<IRevokedTokenCache>();
        revoked.IsRevoked(jti).Returns(true);

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("app.example.com", "some-token");

        await middleware.InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(302);
    }

    [Fact]
    public async Task ValidRequest_CallsNext_AndSetsIdentityHeaders()
    {
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var routeId = Guid.NewGuid();
        var jti = Guid.NewGuid();
        var route = MakeRoute("app.example.com", "jwt", routeId);
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var claims = new JwtClaims(jti, "user@test.com", routeId, "password", "route",
            DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());

        var verifier = Substitute.For<IJwtVerifier>();
        verifier.TryVerify("valid-token", out Arg.Any<JwtClaims?>()).Returns(x =>
        {
            x[1] = claims;
            return true;
        });

        var revoked = Substitute.For<IRevokedTokenCache>();
        revoked.IsRevoked(jti).Returns(false);

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("app.example.com", "valid-token");

        await middleware.InvokeAsync(ctx);

        nextCalled.Should().BeTrue();
        ctx.Request.Headers["X-Limen-User-Id"].ToString().Should().Be("user@test.com");
        ctx.Request.Headers["X-Limen-User-Email"].ToString().Should().Be("user@test.com");
        ctx.Request.Headers["X-Limen-Auth-Method"].ToString().Should().Be("password");
        ctx.Request.Headers["X-Limen-Resource-Id"].ToString().Should().Be(routeId.ToString());
    }

    [Fact]
    public async Task LimenPublicUrlEmpty_AuthRequired_Returns401()
    {
        RequestDelegate next = _ => Task.CompletedTask;

        var route = MakeRoute("app.example.com", "jwt");
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var verifier = Substitute.For<IJwtVerifier>();
        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked, limenPublicUrl: "");
        var ctx = MakeContext("app.example.com");  // no cookie

        await middleware.InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(401);
    }

    [Fact]
    public async Task SsoAuthMethod_DoesNotSetUserEmailHeader()
    {
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var routeId = Guid.NewGuid();
        var jti = Guid.NewGuid();
        var route = MakeRoute("app.example.com", "jwt", routeId);
        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(new[] { route });

        var claims = new JwtClaims(jti, "idp-stable-user-id-not-an-email", routeId, "sso", "strict",
            DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());

        var verifier = Substitute.For<IJwtVerifier>();
        verifier.TryVerify("sso-token", out Arg.Any<JwtClaims?>()).Returns(x =>
        {
            x[1] = claims;
            return true;
        });

        var revoked = Substitute.For<IRevokedTokenCache>();
        revoked.IsRevoked(jti).Returns(false);

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("app.example.com", "sso-token");

        await middleware.InvokeAsync(ctx);

        nextCalled.Should().BeTrue();
        ctx.Request.Headers["X-Limen-User-Id"].ToString().Should().Be("idp-stable-user-id-not-an-email");
        ctx.Request.Headers.ContainsKey("X-Limen-User-Email").Should().BeFalse();
        ctx.Request.Headers["X-Limen-Auth-Method"].ToString().Should().Be("sso");
    }

    [Fact]
    public async Task UnmatchedHost_PassesThroughWithoutAuth()
    {
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(Array.Empty<RouteSpec>());

        var verifier = Substitute.For<IJwtVerifier>();
        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked);

        // Simulate healthz-on-container-IP or any other unmatched-host request
        var ctx = new DefaultHttpContext();
        ctx.Request.Host = new HostString("172.17.0.2");
        ctx.Request.Path = "/healthz";

        await middleware.InvokeAsync(ctx);

        nextCalled.Should().BeTrue();
        ctx.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task InboundSpoofedHeaders_AlwaysStripped()
    {
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var routes = Substitute.For<IRouteStore>();
        routes.Snapshot().Returns(Array.Empty<RouteSpec>());

        var verifier = Substitute.For<IJwtVerifier>();
        var revoked = Substitute.For<IRevokedTokenCache>();

        var middleware = CreateMiddleware(next, routes, verifier, revoked);
        var ctx = MakeContext("unknown.example.com");
        ctx.Request.Headers["X-Limen-User-Id"] = "evil";
        ctx.Request.Headers["X-Limen-User-Email"] = "evil@hack.com";
        ctx.Request.Headers["X-Limen-Auth-Method"] = "spoof";
        ctx.Request.Headers["X-Limen-Resource-Id"] = "bad";

        await middleware.InvokeAsync(ctx);

        nextCalled.Should().BeTrue();
        ctx.Request.Headers.ContainsKey("X-Limen-User-Id").Should().BeFalse();
        ctx.Request.Headers.ContainsKey("X-Limen-User-Email").Should().BeFalse();
        ctx.Request.Headers.ContainsKey("X-Limen-Auth-Method").Should().BeFalse();
        ctx.Request.Headers.ContainsKey("X-Limen-Resource-Id").Should().BeFalse();
    }
}
