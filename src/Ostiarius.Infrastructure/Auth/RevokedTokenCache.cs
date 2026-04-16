using Ostiarius.Application.Common.Interfaces;

namespace Ostiarius.Infrastructure.Auth;

/// <summary>
/// Snapshot-replace black-list of revoked JWT ids.
/// Reads (IsRevoked) and writes (Replace) are concurrency-safe via atomic reference swap on a volatile field.
/// The underlying set is treated as immutable: never mutate _set in place; always Replace.
/// </summary>
public sealed class RevokedTokenCache : IRevokedTokenCache
{
    private volatile IReadOnlySet<Guid> _set = new HashSet<Guid>();

    public bool IsRevoked(Guid jti) => _set.Contains(jti);

    public void Replace(IReadOnlyCollection<Guid> revokedJtis) => _set = new HashSet<Guid>(revokedJtis);
}
