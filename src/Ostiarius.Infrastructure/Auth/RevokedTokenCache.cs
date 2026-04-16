using Ostiarius.Application.Common.Interfaces;

namespace Ostiarius.Infrastructure.Auth;

public sealed class RevokedTokenCache : IRevokedTokenCache
{
    private volatile HashSet<Guid> _set = new();

    public bool IsRevoked(Guid jti) => _set.Contains(jti);

    public void Replace(IReadOnlyCollection<Guid> revokedJtis) => _set = new HashSet<Guid>(revokedJtis);
}
