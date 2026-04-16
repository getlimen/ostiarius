using Ostiarius.Application.Common.Interfaces;
using Ostiarius.Infrastructure.Auth;
using Ostiarius.Infrastructure.Control;
using Ostiarius.Infrastructure.Proxy;
using Yarp.ReverseProxy.Configuration;

var builder = WebApplication.CreateBuilder(args);

#region Configure Services
builder.Services.Configure<OstiariusControlOptions>(builder.Configuration.GetSection("Ostiarius"));

builder.Services.AddSingleton<IRouteStore, RouteStore>();
builder.Services.AddSingleton<IProxyConfigProvider, YarpConfigProvider>();
builder.Services.AddReverseProxy();
builder.Services.AddHostedService<LimenWebSocketClient>();

builder.Services.AddHttpClient("limen-auth");
builder.Services.AddSingleton<IJwtVerifier, Ed25519Verifier>();
builder.Services.AddSingleton<IRevokedTokenCache, RevokedTokenCache>();
builder.Services.AddHostedService<RevokedTokenPoller>();

var useAcme = builder.Configuration.GetValue<bool>("Acme:Enabled");
if (useAcme)
{
    // ACME wiring deferred to Plan 07.
    // LettuceEncrypt-Archon 2.0.0 targets .NET 8 and its registration API mirrors
    // the upstream LettuceEncrypt pattern:
    //   builder.Services
    //       .AddLettuceEncrypt(opts => {
    //           opts.AcceptTermsOfService = true;
    //           opts.EmailAddress = builder.Configuration["Acme:Email"];
    //           opts.UseStagingServer = builder.Configuration.GetValue<bool>("Acme:UseStaging", true);
    //       })
    //       .PersistDataToDirectory(new DirectoryInfo("/data/acme"), null);
    // Uncomment and adjust once the package targets .NET 10 or a compatible binding is confirmed.
}
#endregion

var app = builder.Build();

#region Configure HTTP Pipeline
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));
app.UseMiddleware<AuthMiddleware>();
app.MapReverseProxy();
#endregion

app.Run();
