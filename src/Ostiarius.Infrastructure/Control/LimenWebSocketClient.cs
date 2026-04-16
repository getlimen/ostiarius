using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Limen.Contracts.Common;
using Limen.Contracts.ProxyMessages;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Ostiarius.Application.Common.Interfaces;

namespace Ostiarius.Infrastructure.Control;

public sealed class OstiariusControlOptions
{
    public string LimenUrl { get; set; } = string.Empty;
    public string ProxyNodeId { get; set; } = string.Empty;
    public string AgentSecret { get; set; } = string.Empty;
    public string LimenPublicUrl { get; set; } = string.Empty;
    public int RevokedPollIntervalSeconds { get; set; } = 30;
}

public sealed class LimenWebSocketClient : BackgroundService
{
    private readonly OstiariusControlOptions _options;
    private readonly IRouteStore _routes;
    private readonly ILogger<LimenWebSocketClient> _log;

    public LimenWebSocketClient(
        IOptions<OstiariusControlOptions> options,
        IRouteStore routes,
        ILogger<LimenWebSocketClient> log)
    {
        _options = options.Value;
        _routes = routes;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_options.LimenUrl))
        {
            _log.LogWarning("Ostiarius:LimenUrl not configured; control channel disabled.");
            return;
        }

        var backoff = TimeSpan.FromSeconds(1);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var ws = new ClientWebSocket();
                var uri = new Uri(new Uri(_options.LimenUrl), "/api/proxies/ws");
                await ws.ConnectAsync(uri, ct);
                _log.LogInformation("Proxy WS connected to {Uri}", uri);
                backoff = TimeSpan.FromSeconds(1);

                await SendAsync(ws, ProxyMessageTypes.ProxyAuth,
                    new ProxyAuth(_options.ProxyNodeId, _options.AgentSecret), ct);

                var buf = new byte[16 * 1024];
                while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    var r = await ws.ReceiveAsync(buf, ct);
                    if (r.MessageType == WebSocketMessageType.Close)
                    {
                        break;
                    }

                    if (r.MessageType != WebSocketMessageType.Text)
                    {
                        continue;
                    }

                    using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(buf, 0, r.Count));
                    var type = doc.RootElement.GetProperty("Type").GetString();
                    var payloadEl = doc.RootElement.GetProperty("Payload");

                    if (type == ProxyMessageTypes.ProxyAuthResponse)
                    {
                        var resp = payloadEl.Deserialize<ProxyAuthResponse>();
                        if (resp is not null && !resp.Ok)
                        {
                            _log.LogError("Limen rejected proxy auth: {Reason}", resp.Reason);
                            return;
                        }

                        _log.LogInformation("Limen accepted proxy auth.");
                    }
                    else if (type == ProxyMessageTypes.ApplyRouteSet)
                    {
                        var apply = payloadEl.Deserialize<ApplyRouteSet>();
                        if (apply is not null)
                        {
                            _routes.ReplaceAll(apply.Routes);
                            _log.LogInformation("Applied {N} routes", apply.Routes.Count);
                            await SendAsync(ws, ProxyMessageTypes.RouteSetAck,
                                new RouteSetAck(0, apply.Routes.Count), ct);
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Proxy WS lost; reconnecting in {Backoff}", backoff);
                try { await Task.Delay(backoff, ct); } catch (OperationCanceledException) { break; }
                backoff = TimeSpan.FromSeconds(Math.Min(60, backoff.TotalSeconds * 2));
            }
        }
    }

    private static async Task SendAsync<T>(ClientWebSocket ws, string type, T payload, CancellationToken ct)
    {
        var env = new Envelope<T>(type, ConfigVersion.Zero, payload);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(env);
        await ws.SendAsync(bytes, WebSocketMessageType.Text, true, ct);
    }
}
