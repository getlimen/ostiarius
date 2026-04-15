using Limen.Contracts.ProxyMessages;

namespace Ostiarius.Application.Common.Interfaces;

public interface IRouteStore
{
    IReadOnlyCollection<RouteSpec> Snapshot();
    void ReplaceAll(IEnumerable<RouteSpec> routes);
    event Action? Changed;
}
