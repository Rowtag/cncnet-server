using System.Net;
using MaxMind.Db;
using MaxMind.GeoIP2;

namespace CnCNetServer;

/// <summary>
/// Resolves an IP address to an ISO country code using a local, memory-mapped
/// country database (DB-IP Country Lite / GeoLite2). Opened once, reused.
/// Look-ups run only on the status poll over the client set the tunnel already
/// holds - no per-packet cost. The raw IP is used only for the look-up and is
/// never stored or returned.
/// </summary>
public sealed class GeoResolver : IDisposable
{
    private readonly DatabaseReader? _reader;

    public GeoResolver(string dbPath)
    {
        try
        {
            if (File.Exists(dbPath))
            {
                _reader = new DatabaseReader(dbPath, FileAccessMode.MemoryMapped);
            }
        }
        catch
        {
            _reader = null;
        }
    }

    /// <summary>True when the country database loaded successfully.</summary>
    public bool Available => _reader is not null;

    /// <summary>Returns the ISO country code (e.g. "DE"), or "??" when unknown.</summary>
    public string Resolve(IPAddress address)
    {
        if (_reader is null)
        {
            return "??";
        }

        try
        {
            return _reader.Country(address).Country?.IsoCode ?? "??";
        }
        catch
        {
            return "??";
        }
    }

    public void Dispose() => _reader?.Dispose();
}
