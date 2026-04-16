using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSec.Cryptography;
using Ostiarius.Application.Common.Interfaces;
using Ostiarius.Infrastructure.Control;

namespace Ostiarius.Infrastructure.Auth;

public sealed class Ed25519Verifier : IJwtVerifier
{
    private readonly OstiariusControlOptions _options;
    private readonly IHttpClientFactory _factory;
    private readonly ILogger<Ed25519Verifier> _log;

    private PublicKey? _publicKey;
    private string? _kid;
    private readonly SemaphoreSlim _loadLock = new(1, 1);

    public Ed25519Verifier(
        IOptions<OstiariusControlOptions> options,
        IHttpClientFactory factory,
        ILogger<Ed25519Verifier> log)
    {
        _options = options.Value;
        _factory = factory;
        _log = log;
    }

    public async Task EnsurePublicKeyLoadedAsync(CancellationToken ct)
    {
        if (_publicKey is not null)
        {
            return;
        }

        await _loadLock.WaitAsync(ct);
        try
        {
            if (_publicKey is not null)
            {
                return;
            }

            var delays = new[] { 5, 30, 60, 60, 60 };
            var deadline = DateTimeOffset.UtcNow.AddMinutes(5);

            for (var attempt = 0; DateTimeOffset.UtcNow < deadline; attempt++)
            {
                try
                {
                    var client = _factory.CreateClient("limen-auth");
                    var url = $"{_options.LimenPublicUrl.TrimEnd('/')}/auth/public-key";
                    var response = await client.GetAsync(url, ct);
                    response.EnsureSuccessStatusCode();

                    using var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(ct);
                    if (doc is null)
                    {
                        throw new InvalidOperationException("Empty response from public key endpoint.");
                    }

                    var root = doc.RootElement;
                    var kid = root.GetProperty("kid").GetString() ?? throw new InvalidOperationException("Missing kid.");
                    var publicKeyBase64 = root.GetProperty("publicKey").GetString() ?? throw new InvalidOperationException("Missing publicKey.");
                    var keyBytes = Convert.FromBase64String(publicKeyBase64);

                    _publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, keyBytes, KeyBlobFormat.RawPublicKey);
                    _kid = kid;

                    _log.LogInformation("Loaded Limen Ed25519 public key kid={Kid}", kid);
                    return;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    var delayIdx = Math.Min(attempt, delays.Length - 1);
                    var delaySecs = delays[delayIdx];
                    _log.LogWarning(ex, "Failed to load Limen public key (attempt {Attempt}); retrying in {Delay}s", attempt + 1, delaySecs);

                    if (DateTimeOffset.UtcNow.AddSeconds(delaySecs) >= deadline)
                    {
                        break;
                    }

                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(delaySecs), ct);
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                }
            }

            _log.LogError("Could not load Limen public key within 5 minutes; JWT verification disabled until next reload.");
        }
        finally
        {
            _loadLock.Release();
        }
    }

    public bool TryVerify(string jwt, out JwtClaims? claims)
    {
        claims = null;

        if (_publicKey is null)
        {
            return false;
        }

        try
        {
            var parts = jwt.Split('.');
            if (parts.Length != 3)
            {
                return false;
            }

            var signingInput = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");
            var sig = Base64UrlDecode(parts[2]);

            if (!SignatureAlgorithm.Ed25519.Verify(_publicKey, signingInput, sig))
            {
                return false;
            }

            var payloadBytes = Base64UrlDecode(parts[1]);
            using var doc = JsonDocument.Parse(payloadBytes);
            var root = doc.RootElement;

            var jti = Guid.Parse(root.GetProperty("jti").GetString()!);
            var sub = root.GetProperty("sub").GetString()!;
            var routeId = Guid.Parse(root.GetProperty("routeId").GetString()!);
            var authMethod = root.GetProperty("authMethod").GetString()!;
            var cookieScope = root.GetProperty("cookieScope").GetString()!;
            var exp = root.GetProperty("exp").GetInt64();

            claims = new JwtClaims(jti, sub, routeId, authMethod, cookieScope, exp);
            return true;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "JWT verification failed");
            return false;
        }
    }

    private static byte[] Base64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }

        return Convert.FromBase64String(padded);
    }
}
