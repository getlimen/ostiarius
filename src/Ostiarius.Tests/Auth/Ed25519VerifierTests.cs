using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSec.Cryptography;
using NSubstitute;
using Ostiarius.Application.Common.Interfaces;
using Ostiarius.Infrastructure.Auth;
using Ostiarius.Infrastructure.Control;
using Xunit;

namespace Ostiarius.Tests.Auth;

public sealed class Ed25519VerifierTests
{
    private static readonly SignatureAlgorithm Algo = SignatureAlgorithm.Ed25519;

    private static string BuildJwt(Key privateKey, Guid jti, Guid routeId, string sub, long exp, bool tamperPayload = false)
    {
        var header = Base64UrlEncode(Encoding.UTF8.GetBytes("""{"alg":"EdDSA","typ":"JWT"}"""));

        var payload = new
        {
            jti = jti.ToString(),
            sub,
            routeId = routeId.ToString(),
            authMethod = "password",
            cookieScope = "route",
            exp
        };
        var payloadJson = JsonSerializer.Serialize(payload);
        var encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

        var signingInput = Encoding.UTF8.GetBytes($"{header}.{encodedPayload}");
        var sig = Algo.Sign(privateKey, signingInput);

        if (tamperPayload)
        {
            var tamperedPayload = new
            {
                jti = jti.ToString(),
                sub = "HACKER",
                routeId = routeId.ToString(),
                authMethod = "password",
                cookieScope = "route",
                exp
            };
            var tamperedJson = JsonSerializer.Serialize(tamperedPayload);
            encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(tamperedJson));
        }

        return $"{header}.{encodedPayload}.{Base64UrlEncode(sig)}";
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static (Ed25519Verifier verifier, Key privateKey, PublicKey publicKey) CreateVerifier()
    {
        var creationParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        var privateKey = Key.Create(Algo, creationParams);
        var publicKey = privateKey.PublicKey;

        var publicKeyBytes = publicKey.Export(KeyBlobFormat.RawPublicKey);
        var publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);

        var fakeJson = JsonSerializer.Serialize(new { kid = "test-kid", alg = "EdDSA", publicKey = publicKeyBase64 });

        var httpClient = new HttpClient(new FakeHttpMessageHandler(fakeJson));
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("limen-auth").Returns(httpClient);

        var options = Options.Create(new OstiariusControlOptions
        {
            LimenPublicUrl = "https://limen.example.com"
        });

        var verifier = new Ed25519Verifier(options, factory, NullLogger<Ed25519Verifier>.Instance);
        return (verifier, privateKey, publicKey);
    }

    [Fact]
    public async Task TryVerify_ValidJwt_ReturnsTrueWithCorrectClaims()
    {
        var (verifier, privateKey, _) = CreateVerifier();
        await verifier.EnsurePublicKeyLoadedAsync(CancellationToken.None);

        var jti = Guid.NewGuid();
        var routeId = Guid.NewGuid();
        var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var jwt = BuildJwt(privateKey, jti, routeId, "user@example.com", exp);

        var result = verifier.TryVerify(jwt, out var claims);

        result.Should().BeTrue();
        claims.Should().NotBeNull();
        claims!.Jti.Should().Be(jti);
        claims.Subject.Should().Be("user@example.com");
        claims.RouteId.Should().Be(routeId);
        claims.AuthMethod.Should().Be("password");
        claims.CookieScope.Should().Be("route");
        claims.ExpiresAtUnix.Should().Be(exp);
    }

    [Fact]
    public async Task TryVerify_TamperedPayload_ReturnsFalse()
    {
        var (verifier, privateKey, _) = CreateVerifier();
        await verifier.EnsurePublicKeyLoadedAsync(CancellationToken.None);

        var jti = Guid.NewGuid();
        var routeId = Guid.NewGuid();
        var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var jwt = BuildJwt(privateKey, jti, routeId, "user@example.com", exp, tamperPayload: true);

        var result = verifier.TryVerify(jwt, out var claims);

        result.Should().BeFalse();
        claims.Should().BeNull();
    }

    [Fact]
    public async Task TryVerify_BadSignature_ReturnsFalse()
    {
        var (verifier, _, _) = CreateVerifier();
        await verifier.EnsurePublicKeyLoadedAsync(CancellationToken.None);

        // Build JWT with a different key
        var creationParams = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        var otherKey = Key.Create(Algo, creationParams);
        var jti = Guid.NewGuid();
        var routeId = Guid.NewGuid();
        var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var jwt = BuildJwt(otherKey, jti, routeId, "user@example.com", exp);

        var result = verifier.TryVerify(jwt, out var claims);

        result.Should().BeFalse();
        claims.Should().BeNull();
    }

    [Fact]
    public async Task TryVerify_MalformedJwt_ReturnsFalse()
    {
        var (verifier, _, _) = CreateVerifier();
        await verifier.EnsurePublicKeyLoadedAsync(CancellationToken.None);

        var result = verifier.TryVerify("not.a.valid.jwt.string", out var claims);

        result.Should().BeFalse();
        claims.Should().BeNull();
    }

    [Fact]
    public async Task TryVerify_NoPublicKey_ReturnsFalse()
    {
        // Don't call EnsurePublicKeyLoadedAsync
        var factory = Substitute.For<IHttpClientFactory>();
        var options = Options.Create(new OstiariusControlOptions { LimenPublicUrl = "" });
        var verifier = new Ed25519Verifier(options, factory, NullLogger<Ed25519Verifier>.Instance);

        var result = verifier.TryVerify("any.jwt.here", out var claims);

        result.Should().BeFalse();
        claims.Should().BeNull();
    }

    private sealed class FakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly string _responseJson;

        public FakeHttpMessageHandler(string responseJson)
        {
            _responseJson = responseJson;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(_responseJson, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }
}
