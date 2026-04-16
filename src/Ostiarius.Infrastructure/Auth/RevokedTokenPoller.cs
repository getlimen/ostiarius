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

        var interval = _options.RevokedPollIntervalSeconds == 0
            ? TimeSpan.FromSeconds(30)
            : TimeSpan.FromSeconds(_options.RevokedPollIntervalSeconds);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await PollOnce(ct);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Revoked-token poll failed; keeping stale cache");
            }

            try
            {
                await Task.Delay(interval, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task PollOnce(CancellationToken ct)
    {
        var client = _factory.CreateClient("limen-auth");
        var url = $"{_options.LimenPublicUrl.TrimEnd('/')}/auth/revoked";
        var response = await client.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync(ct);

        if (string.IsNullOrWhiteSpace(body))
        {
            _log.LogWarning("Empty response from revoked tokens endpoint; keeping stale cache.");
            return;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body);
        }
        catch (JsonException ex)
        {
            _log.LogWarning(ex, "Non-JSON response from revoked tokens endpoint; keeping stale cache.");
            return;
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                _log.LogWarning("Revoked tokens response is not a JSON array (got {Kind}); keeping stale cache.", doc.RootElement.ValueKind);
                return;
            }

            var jtis = new List<Guid>();
            foreach (var element in doc.RootElement.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                string? jtiStr = null;
                if (element.TryGetProperty("jti", out var jtiProp) || element.TryGetProperty("Jti", out jtiProp))
                {
                    jtiStr = jtiProp.GetString();
                }

                if (Guid.TryParse(jtiStr, out var jti))
                {
                    jtis.Add(jti);
                }
            }

            _cache.Replace(jtis);
            _log.LogDebug("Refreshed revoked token cache: {Count} entries", jtis.Count);
        }
    }
}
