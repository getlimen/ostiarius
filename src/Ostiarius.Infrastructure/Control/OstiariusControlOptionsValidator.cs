using System;
using Microsoft.Extensions.Options;

namespace Ostiarius.Infrastructure.Control;

public sealed class OstiariusControlOptionsValidator : IValidateOptions<OstiariusControlOptions>
{
    public ValidateOptionsResult Validate(string? name, OstiariusControlOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.LimenPublicUrl))
        {
            // Empty is allowed (means resource auth wall is disabled — middleware logs warning + 401s on auth-required routes)
            return ValidateOptionsResult.Success;
        }

        if (!Uri.TryCreate(options.LimenPublicUrl, UriKind.Absolute, out var uri))
        {
            return ValidateOptionsResult.Fail("Ostiarius:LimenPublicUrl must be an absolute URL");
        }

        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            return ValidateOptionsResult.Success;
        }

        if (uri.Scheme == Uri.UriSchemeHttp && (uri.IsLoopback || uri.Host == "limen"))
        {
            // Allow http for local dev (loopback) and for the in-network e2e harness (host name "limen" inside docker network)
            return ValidateOptionsResult.Success;
        }

        return ValidateOptionsResult.Fail(
            $"Ostiarius:LimenPublicUrl scheme '{uri.Scheme}' is not allowed. Use https for production; http only on loopback/dev.");
    }
}
