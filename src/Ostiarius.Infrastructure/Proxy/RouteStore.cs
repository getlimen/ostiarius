using System.Collections.Concurrent;
using Limen.Contracts.ProxyMessages;
using Ostiarius.Application.Common.Interfaces;

namespace Ostiarius.Infrastructure.Proxy;

public sealed class RouteStore : IRouteStore
{
    private readonly ConcurrentDictionary<Guid, RouteSpec> _routes = new();
    public event Action? Changed;

    public IReadOnlyCollection<RouteSpec> Snapshot() => _routes.Values.ToArray();

    public void ReplaceAll(IEnumerable<RouteSpec> routes)
    {
        _routes.Clear();
        foreach (var r in routes)
        {
            _routes[r.RouteId] = r;
        }

        Changed?.Invoke();
    }
}
