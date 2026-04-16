namespace Ostiarius.Application.Common.Interfaces;

public sealed record JwtClaims(
    Guid Jti,
    /// <summary>
    /// JWT 'sub' claim. Per limen issuance contract:
    /// - "password" and "allowlist" auth methods: Subject IS the user's email.
    /// - "sso" auth method: Subject is the IdP-stable user id (may not be an email).
    /// </summary>
    string Subject,
    Guid RouteId,
    /// <summary>One of "password", "allowlist", "sso".</summary>
    string AuthMethod,
    /// <summary>
    /// "strict" or "domain". Currently INFORMATIONAL — the middleware does not enforce per-scope cookie behavior.
    /// v1 only supports "strict"; future PR may differentiate.
    /// </summary>
    string CookieScope,
    long ExpiresAtUnix);

public interface IJwtVerifier
{
    bool TryVerify(string jwt, out JwtClaims? claims);
    Task EnsurePublicKeyLoadedAsync(CancellationToken ct);
}
