using FluentAssertions;
using Ostiarius.Infrastructure.Auth;
using Xunit;

namespace Ostiarius.Tests.Auth;

public sealed class RevokedTokenCacheTests
{
    [Fact]
    public void IsRevoked_AfterReplace_ReturnsTrueForRevokedJti()
    {
        var cache = new RevokedTokenCache();
        var jti = Guid.NewGuid();

        cache.Replace(new[] { jti });

        cache.IsRevoked(jti).Should().BeTrue();
    }

    [Fact]
    public void IsRevoked_JtiNotInList_ReturnsFalse()
    {
        var cache = new RevokedTokenCache();
        var revoked = Guid.NewGuid();
        var notRevoked = Guid.NewGuid();

        cache.Replace(new[] { revoked });

        cache.IsRevoked(notRevoked).Should().BeFalse();
    }

    [Fact]
    public void Replace_WithEmptyCollection_ClearsCache()
    {
        var cache = new RevokedTokenCache();
        var jti = Guid.NewGuid();

        cache.Replace(new[] { jti });
        cache.Replace(Array.Empty<Guid>());

        cache.IsRevoked(jti).Should().BeFalse();
    }

    [Fact]
    public void Replace_ReplacesEntireSet()
    {
        var cache = new RevokedTokenCache();
        var old = Guid.NewGuid();
        var newJti = Guid.NewGuid();

        cache.Replace(new[] { old });
        cache.Replace(new[] { newJti });

        cache.IsRevoked(old).Should().BeFalse();
        cache.IsRevoked(newJti).Should().BeTrue();
    }

    [Fact]
    public void IsRevoked_EmptyCache_ReturnsFalse()
    {
        var cache = new RevokedTokenCache();
        cache.IsRevoked(Guid.NewGuid()).Should().BeFalse();
    }
}
