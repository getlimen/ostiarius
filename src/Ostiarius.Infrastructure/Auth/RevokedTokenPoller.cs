using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Ostiarius.Application.Common.Interfaces;
using Ostiarius.Infrastructure.Control;

namespace Ostiarius.Infrastructure.Auth;

public sealed class RevokedTokenPoller : BackgroundService
{
    private readonly IRevokedTokenCache _cache;
    private readonly OstiariusControlOptions _options;
    private readonly IHttpClientFactory _factory;
    private readonly ILogger<RevokedTokenPoller> _log;

    public RevokedTokenPoller(
        IRevokedTokenCache cache,
        IOptions<OstiariusControlOptions> options,
        IHttpClientFactory factory,
        ILogger<RevokedTokenPoller> log)
    {
        _cache = cache;
        _options = options.Value;
        _factory = factory;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_options.LimenPublicUrl))
        {
            _log.LogWarning("LimenPublicUrl not configured; revoked token polling disabled.");
            return;
        }

        var interval = TimeSpan.FromSeconds(
            _options.RevokedPollIntervalSeconds > 0 ? _options.RevokedPollIntervalSeconds : 30);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            try
            {
                var client = _factory.CreateClient("limen-auth");
                var url = $"{_options.LimenPublicUrl.TrimEnd('/')}/auth/revoked";
                var response = await client.GetAsync(url, ct);
                response.EnsureSuccessStatusCode();

                using var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(ct);
                if (doc is null)
                {
                    _log.LogWarning("Empty response from revoked tokens endpoint; keeping stale cache.");
                    continue;
                }

                var jtis = new List<Guid>();
                foreach (var element in doc.RootElement.EnumerateArray())
                {
                    var jtiStr = element.GetProperty("jti").GetString();
                    if (Guid.TryParse(jtiStr, out var jti))
                    {
                        jtis.Add(jti);
                    }
                }

                _cache.Replace(jtis);
                _log.LogDebug("Refreshed revoked token cache: {Count} entries", jtis.Count);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Failed to refresh revoked token cache; keeping stale cache.");
            }
        }
    }
}
