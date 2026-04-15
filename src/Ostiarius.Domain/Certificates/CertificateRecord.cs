namespace Ostiarius.Domain.Certificates;

public class CertificateRecord
{
    public string Hostname { get; set; } = string.Empty;
    public byte[] PfxBytes { get; set; } = Array.Empty<byte>();
    public DateTimeOffset IssuedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
