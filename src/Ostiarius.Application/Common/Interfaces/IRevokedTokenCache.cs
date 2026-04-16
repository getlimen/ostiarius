namespace Ostiarius.Application.Common.Interfaces;

public interface IRevokedTokenCache
{
    bool IsRevoked(Guid jti);
    void Replace(IReadOnlyCollection<Guid> revokedJtis);
}
