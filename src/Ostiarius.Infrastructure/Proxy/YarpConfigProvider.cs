using Microsoft.Extensions.Primitives;
using Ostiarius.Application.Common.Interfaces;
using Yarp.ReverseProxy.Configuration;

namespace Ostiarius.Infrastructure.Proxy;

public sealed class YarpConfigProvider : IProxyConfigProvider
{
    private readonly IRouteStore _store;
    private volatile InMemoryConfig _config;

    public YarpConfigProvider(IRouteStore store)
    {
        _store = store;
        _config = Build(store.Snapshot());
        store.Changed += OnChanged;
    }

    private void OnChanged()
    {
        var old = _config;
        _config = Build(_store.Snapshot());
        old.SignalChange();
    }

    public IProxyConfig GetConfig() => _config;

    private static InMemoryConfig Build(IReadOnlyCollection<Limen.Contracts.ProxyMessages.RouteSpec> specs)
    {
        var routes = specs.Select(r => new RouteConfig
        {
            RouteId = r.RouteId.ToString(),
            ClusterId = $"cluster-{r.RouteId}",
            Match = new RouteMatch { Hosts = new[] { r.Hostname } },
        }).ToList();

        var clusters = specs.Select(r => new ClusterConfig
        {
            ClusterId = $"cluster-{r.RouteId}",
            Destinations = new Dictionary<string, DestinationConfig>
            {
                ["dest1"] = new() { Address = r.UpstreamUrl }
            }
        }).ToList();

        return new InMemoryConfig(routes, clusters);
    }

    private sealed class InMemoryConfig : IProxyConfig
    {
        private readonly CancellationTokenSource _cts = new();

        public InMemoryConfig(IReadOnlyList<RouteConfig> routes, IReadOnlyList<ClusterConfig> clusters)
        {
            Routes = routes;
            Clusters = clusters;
            ChangeToken = new CancellationChangeToken(_cts.Token);
        }

        public IReadOnlyList<RouteConfig> Routes { get; }
        public IReadOnlyList<ClusterConfig> Clusters { get; }
        public IChangeToken ChangeToken { get; }
        public void SignalChange() => _cts.Cancel();
    }
}
