namespace Ostiarius.Application.Common.Interfaces;

public sealed record JwtClaims(
    Guid Jti,
    string Subject,
    Guid RouteId,
    string AuthMethod,
    string CookieScope,
    long ExpiresAtUnix);

public interface IJwtVerifier
{
    bool TryVerify(string jwt, out JwtClaims? claims);
    Task EnsurePublicKeyLoadedAsync(CancellationToken ct);
}
