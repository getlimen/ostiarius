using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Ostiarius.Application.Common.Interfaces;
using Ostiarius.Infrastructure.Auth;
using Ostiarius.Infrastructure.Control;
using Xunit;

namespace Ostiarius.Tests.Auth;

public sealed class RevokedTokenPollerTests
{
    private static (RevokedTokenPoller poller, IRevokedTokenCache cache) CreatePoller(
        string responseBody,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var cache = Substitute.For<IRevokedTokenCache>();
        var factory = Substitute.For<IHttpClientFactory>();
        var httpClient = new HttpClient(new StubHttpMessageHandler(responseBody, statusCode));
        factory.CreateClient("limen-auth").Returns(httpClient);

        var options = Options.Create(new OstiariusControlOptions
        {
            LimenPublicUrl = "https://limen.example.com",
            RevokedPollIntervalSeconds = 3600 // long interval so we only run once in tests
        });

        var poller = new RevokedTokenPoller(cache, options, factory, NullLogger<RevokedTokenPoller>.Instance);
        return (poller, cache);
    }

    [Fact]
    public async Task ValidArray_ReplacesCacheWithParsedJtis()
    {
        var jti1 = Guid.NewGuid();
        var jti2 = Guid.NewGuid();
        var body = $"""[{{"jti":"{jti1}"}},{{"jti":"{jti2}"}}]""";
        var (poller, cache) = CreatePoller(body);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await RunOnePollAsync(poller, cts.Token);

        cache.Received(1).Replace(Arg.Is<IReadOnlyCollection<Guid>>(list =>
            list.Count == 2 && list.Contains(jti1) && list.Contains(jti2)));
    }

    [Fact]
    public async Task EmptyArray_ReplacesCacheWithEmptyList()
    {
        var (poller, cache) = CreatePoller("[]");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await RunOnePollAsync(poller, cts.Token);

        cache.Received(1).Replace(Arg.Is<IReadOnlyCollection<Guid>>(list => list.Count == 0));
    }

    [Fact]
    public async Task NonJsonBody_KeepsStaleCache()
    {
        var (poller, cache) = CreatePoller("not-json-at-all");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await RunOnePollAsync(poller, cts.Token);

        cache.DidNotReceive().Replace(Arg.Any<IReadOnlyCollection<Guid>>());
    }

    [Fact]
    public async Task ObjectBody_KeepsStaleCache()
    {
        var (poller, cache) = CreatePoller("""{"error":"not an array"}""");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await RunOnePollAsync(poller, cts.Token);

        cache.DidNotReceive().Replace(Arg.Any<IReadOnlyCollection<Guid>>());
    }

    [Fact]
    public async Task ServerError_KeepsStaleCache()
    {
        var (poller, cache) = CreatePoller("Internal Server Error", HttpStatusCode.InternalServerError);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await RunOnePollAsync(poller, cts.Token);

        cache.DidNotReceive().Replace(Arg.Any<IReadOnlyCollection<Guid>>());
    }

    /// <summary>
    /// Runs ExecuteAsync until at least one poll has completed, then cancels.
    /// We exploit the fact that ExecuteAsync polls immediately on startup (I5).
    /// After the first PollOnce completes, the loop waits on Task.Delay — we cancel then.
    /// </summary>
    private static async Task RunOnePollAsync(RevokedTokenPoller poller, CancellationToken externalCt)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);

        // Start the background service
        await poller.StartAsync(cts.Token);

        // Give it a moment to complete the first poll (it is immediate now)
        await Task.Delay(200, externalCt);

        // Stop the service
        cts.Cancel();
        await poller.StopAsync(CancellationToken.None);
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly string _body;
        private readonly HttpStatusCode _statusCode;

        public StubHttpMessageHandler(string body, HttpStatusCode statusCode = HttpStatusCode.OK)
        {
            _body = body;
            _statusCode = statusCode;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }
}
