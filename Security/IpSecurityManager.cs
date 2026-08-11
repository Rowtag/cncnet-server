using System.Collections.Concurrent;
using System.Net;
using CnCNetServer.Configuration;
using Serilog;

namespace CnCNetServer.Security;

/// <summary>
/// Manages IP-based security including rate limiting, blacklisting, and DDoS protection.
/// Thread-safe for concurrent access from multiple tunnel handlers.
/// </summary>
/// <remarks>
/// Every method a tunnel calls here sits on the per-packet path, so all of them are allocation-free
/// and none scale with the number of tracked IPs or blacklist entries. Addresses are keyed by their
/// numeric IPv4 form to keep that true - string keys would mean allocating and hashing a string for
/// every packet received.
/// </remarks>
public sealed class IpSecurityManager : IDisposable
{
    private readonly ILogger _logger;
    private readonly SecurityOptions _options;
    private readonly Timer _cleanupTimer;
    private readonly Timer _blacklistRefreshTimer;

    // Rate limiting: tracks request counts per IP, keyed by numeric IPv4 address.
    private readonly ConcurrentDictionary<uint, RateLimitEntry> _rateLimits = new();

    // Local blacklist: IPs that exceeded limits.
    private readonly ConcurrentDictionary<uint, DateTime> _localBlacklist = new();

    // External blacklists, single addresses and CIDR networks alike, as one searchable range set.
    // Replaced wholesale on refresh; readers take the reference once and never see a partial swap.
    private volatile IpRangeSet _externalBlacklist = IpRangeSet.Empty;

    // Tracks _rateLimits.Count without paying for it. ConcurrentDictionary.Count takes every one
    // of the dictionary's internal locks, and this is read on the ping path for the global cap.
    private int _trackedIpCount;

    // Statistics
    private long _totalConnections;
    private long _blockedByLocalBlacklist;
    private long _blockedByExternalBlacklist;

    private const int CleanupIntervalSeconds = 60;
    private const int BlacklistRefreshIntervalHours = 1;

    public IpSecurityManager(SecurityOptions options, ILogger logger)
    {
        _options = options;
        _logger = logger.ForContext<IpSecurityManager>();

        _cleanupTimer = new Timer(
            CleanupExpiredEntries,
            null,
            TimeSpan.FromSeconds(CleanupIntervalSeconds),
            TimeSpan.FromSeconds(CleanupIntervalSeconds));

        _blacklistRefreshTimer = new Timer(
            async _ => await RefreshExternalBlacklistsAsync(),
            null,
            TimeSpan.Zero,
            TimeSpan.FromHours(BlacklistRefreshIntervalHours));
    }

    /// <summary>
    /// Checks if an IP address is allowed to connect (not blacklisted).
    /// </summary>
    public bool IsConnectionAllowed(IPAddress address)
        => IpRangeSet.TryGetKey(address, out var key) ? IsConnectionAllowed(key) : true;

    /// <summary>
    /// Checks if an address, already in numeric form, is allowed to connect. Preferred on packet
    /// paths that have decoded the address themselves.
    /// </summary>
    public bool IsConnectionAllowed(uint address)
    {
        Interlocked.Increment(ref _totalConnections);

        // Check local blacklist
        if (_localBlacklist.TryGetValue(address, out var expiry))
        {
            if (DateTime.UtcNow < expiry)
            {
                Interlocked.Increment(ref _blockedByLocalBlacklist);
                return false;
            }

            _localBlacklist.TryRemove(address, out _);
        }

        // Check external blacklist (snapshot - safe for concurrent reads)
        if (_externalBlacklist.Contains(address))
        {
            Interlocked.Increment(ref _blockedByExternalBlacklist);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Checks if a ping request from an IP is within rate limits.
    /// </summary>
    public bool IsPingAllowed(IPAddress address, int maxPerIp, int maxGlobal)
        => !IpRangeSet.TryGetKey(address, out var key) || IsPingAllowed(key, maxPerIp, maxGlobal);

    /// <inheritdoc cref="IsPingAllowed(IPAddress, int, int)"/>
    public bool IsPingAllowed(uint address, int maxPerIp, int maxGlobal)
    {
        if (Volatile.Read(ref _trackedIpCount) >= maxGlobal)
            return false;

        return GetOrAddRateLimitEntry(address).IncrementPingCount() <= maxPerIp;
    }

    /// <summary>
    /// Tracks a connection for rate limiting purposes. Returns false if the IP is already at
    /// <paramref name="maxConnectionsPerIp"/>, in which case nothing is tracked and the caller
    /// must not create a session.
    /// </summary>
    /// <remarks>
    /// The count is rolled back when the limit is exceeded, because leaving it raised would be
    /// self-reinforcing: a rejected client never gets a mapping, so <see cref="ReleaseConnection"/>
    /// never runs for it and each retry pushes the count further past the limit. The IP could then
    /// never connect again, since <see cref="CleanupExpiredEntries"/> only evicts entries at zero.
    /// </remarks>
    public bool TrackConnection(IPAddress address, int maxConnectionsPerIp)
        => !IpRangeSet.TryGetKey(address, out var key) || TrackConnection(key, maxConnectionsPerIp);

    /// <inheritdoc cref="TrackConnection(IPAddress, int)"/>
    public bool TrackConnection(uint address, int maxConnectionsPerIp)
    {
        var entry = GetOrAddRateLimitEntry(address);

        if (entry.IncrementConnectionCount() <= maxConnectionsPerIp)
            return true;

        entry.DecrementConnectionCount();
        return false;
    }

    /// <summary>
    /// Decrements the connection count for an IP when a client disconnects.
    /// </summary>
    public void ReleaseConnection(IPAddress address)
    {
        if (IpRangeSet.TryGetKey(address, out var key))
            ReleaseConnection(key);
    }

    /// <inheritdoc cref="ReleaseConnection(IPAddress)"/>
    public void ReleaseConnection(uint address)
    {
        if (_rateLimits.TryGetValue(address, out var entry))
            entry.DecrementConnectionCount();
    }

    /// <summary>
    /// Looks up an IP's rate limit entry, creating it if needed, and keeps
    /// <see cref="_trackedIpCount"/> in step with the dictionary.
    /// </summary>
    /// <remarks>
    /// Deliberately not <c>GetOrAdd</c> with a factory: that factory can run more than once under
    /// contention, which would over-count the tracked IPs and slowly close the global ping cap.
    /// </remarks>
    private RateLimitEntry GetOrAddRateLimitEntry(uint address)
    {
        if (_rateLimits.TryGetValue(address, out var entry))
            return entry;

        var created = new RateLimitEntry();
        if (_rateLimits.TryAdd(address, created))
        {
            Interlocked.Increment(ref _trackedIpCount);
            return created;
        }

        return _rateLimits.TryGetValue(address, out entry) ? entry : created;
    }

    /// <summary>
    /// Adds an IP to the local blacklist.
    /// </summary>
    public void AddToBlacklist(IPAddress address)
    {
        if (!IpRangeSet.TryGetKey(address, out var key))
            return;

        var expiry = DateTime.UtcNow.AddHours(_options.IpBlacklistDurationHours);
        _localBlacklist[key] = expiry;
        _logger.Warning("IP {IP} added to local blacklist until {Expiry}", IpAnonymizer.Anonymize(address), expiry);
    }

    /// <summary>
    /// Gets all currently blocked IPs from the local blacklist.
    /// </summary>
    public IEnumerable<BlockedIpInfo> GetBlockedIps()
    {
        var now = DateTime.UtcNow;
        return _localBlacklist
            .Where(kvp => kvp.Value > now)
            .Select(kvp => new BlockedIpInfo
            {
                IpAddress = IpRangeSet.ToDisplayString(kvp.Key),
                ExpiresAt = kvp.Value,
                RemainingMinutes = (int)(kvp.Value - now).TotalMinutes
            })
            .OrderByDescending(x => x.RemainingMinutes);
    }

    /// <summary>
    /// Removes an IP from the local blacklist.
    /// </summary>
    public bool RemoveFromBlacklist(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var parsed) || !IpRangeSet.TryGetKey(parsed, out var key))
            return false;

        var removed = _localBlacklist.TryRemove(key, out _);
        if (removed)
            _logger.Warning("IP {IP} manually removed from local blacklist", IpAnonymizer.Anonymize(ipAddress));
        return removed;
    }

    /// <summary>
    /// Resets rate limit counters (called periodically by heartbeat).
    /// </summary>
    public void ResetRateLimits()
    {
        foreach (var entry in _rateLimits.Values)
            entry.ResetPingCount();
    }

    /// <summary>
    /// Gets current security statistics.
    /// </summary>
    public SecurityStatistics GetStatistics()
    {
        var externalBlacklist = _externalBlacklist;

        return new SecurityStatistics
        {
            TrackedIps = Volatile.Read(ref _trackedIpCount),
            LocalBlacklistCount = _localBlacklist.Count,
            ExternalBlacklistCount = externalBlacklist.AddressCount + externalBlacklist.NetworkCount,
            TotalConnections = Interlocked.Read(ref _totalConnections),
            BlockedByLocalBlacklist = Interlocked.Read(ref _blockedByLocalBlacklist),
            BlockedByExternalBlacklist = Interlocked.Read(ref _blockedByExternalBlacklist)
        };
    }

    /// <summary>
    /// Refreshes external IP blacklists from configured URLs.
    /// Builds new collections atomically, then swaps – no downtime, no partial state.
    /// </summary>
    public async Task RefreshExternalBlacklistsAsync()
    {
        if (_options.ExternalBlacklistUrls.Length == 0)
            return;

        _logger.Information("Refreshing external IP blacklists...");

        // Build the new set – the old one remains fully active until the swap at the end.
        var ranges = new List<(uint Start, uint End)>();

        var totalIps = 0;
        var totalNetworks = 0;
        var successfulSources = 0;

        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        foreach (var url in _options.ExternalBlacklistUrls)
        {
            try
            {
                var content = await httpClient.GetStringAsync(url);
                var (ips, networks) = ParseBlacklist(content, ranges);
                totalIps += ips;
                totalNetworks += networks;
                successfulSources++;
            }
            catch (Exception ex)
            {
                _logger.Warning("Failed to load blacklist from {Url}: {Error}", url, ex.Message);
            }
        }

        // Every source failed – keep what we already have rather than dropping protection.
        if (successfulSources == 0)
        {
            _logger.Warning("No external blacklist source could be reached; keeping the previous list");
            return;
        }

        var newBlacklist = IpRangeSet.Build(ranges, totalIps, totalNetworks);

        // Atomic swap – readers instantly see the new complete list.
        _externalBlacklist = newBlacklist;

        _logger.Information(
            "External blacklist loaded: {IpCount} IPs, {NetworkCount} networks from {Success}/{Total} sources ({RangeCount} merged ranges)",
            totalIps, totalNetworks, successfulSources, _options.ExternalBlacklistUrls.Length, newBlacklist.RangeCount);
    }

    private static (int ips, int networks) ParseBlacklist(string content, List<(uint Start, uint End)> ranges)
    {
        var ips = 0;
        var networks = 0;

        foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#') || trimmed.StartsWith(';'))
                continue;

            if (trimmed.Contains('/'))
            {
                if (TryParseCidr(trimmed, out var start, out var end))
                {
                    ranges.Add((start, end));
                    networks++;
                }
            }
            else if (IPAddress.TryParse(trimmed, out var address) && IpRangeSet.TryGetKey(address, out var key))
            {
                // A single address is just a one-entry range, so it shares the same lookup.
                ranges.Add((key, key));
                ips++;
            }
        }

        return (ips, networks);
    }

    /// <summary>
    /// Parses a CIDR block into the inclusive numeric range it covers.
    /// </summary>
    private static bool TryParseCidr(string cidr, out uint start, out uint end)
    {
        start = 0;
        end = 0;

        var separator = cidr.IndexOf('/');
        if (separator < 0)
            return false;

        // Sliced rather than Split so parsing a blacklist of tens of thousands of lines does not
        // allocate an array per line.
        var addressPart = cidr.AsSpan(0, separator).Trim();
        var prefixPart = cidr.AsSpan(separator + 1).Trim();

        if (!IPAddress.TryParse(addressPart, out var address) || !IpRangeSet.TryGetKey(address, out var network))
            return false;

        if (!int.TryParse(prefixPart, out var prefixLength) || prefixLength < 0 || prefixLength > 32)
            return false;

        var mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        start = network & mask;
        end = start | ~mask;
        return true;
    }

    private void CleanupExpiredEntries(object? state)
    {
        var now = DateTime.UtcNow;

        foreach (var kvp in _localBlacklist)
        {
            if (now >= kvp.Value)
                _localBlacklist.TryRemove(kvp.Key, out _);
        }

        var cutoff = now.AddMinutes(-5);
        foreach (var kvp in _rateLimits)
        {
            if (kvp.Value.LastActivity < cutoff && kvp.Value.ConnectionCount == 0 &&
                _rateLimits.TryRemove(kvp.Key, out _))
            {
                Interlocked.Decrement(ref _trackedIpCount);
            }
        }
    }

    public void Dispose()
    {
        _cleanupTimer.Dispose();
        _blacklistRefreshTimer.Dispose();
    }
}

internal sealed class RateLimitEntry
{
    private int _pingCount;
    private int _connectionCount;

    public DateTime LastActivity { get; private set; } = DateTime.UtcNow;
    public int ConnectionCount => Volatile.Read(ref _connectionCount);

    public int IncrementPingCount() { LastActivity = DateTime.UtcNow; return Interlocked.Increment(ref _pingCount); }
    public void ResetPingCount() => Interlocked.Exchange(ref _pingCount, 0);
    public int IncrementConnectionCount() { LastActivity = DateTime.UtcNow; return Interlocked.Increment(ref _connectionCount); }

    /// <summary>
    /// Releases one tracked connection, never dropping below zero. The floor matters because a
    /// negative count would both hand the IP extra headroom and make the entry permanently
    /// ineligible for cleanup, which only evicts entries sitting at exactly zero.
    /// </summary>
    public void DecrementConnectionCount()
    {
        int current;
        do
        {
            current = Volatile.Read(ref _connectionCount);
            if (current <= 0)
                return;
        }
        while (Interlocked.CompareExchange(ref _connectionCount, current - 1, current) != current);
    }
}

public sealed class SecurityStatistics
{
    public int TrackedIps { get; init; }
    public int LocalBlacklistCount { get; init; }
    public int ExternalBlacklistCount { get; init; }
    public long TotalConnections { get; init; }
    public long BlockedByLocalBlacklist { get; init; }
    public long BlockedByExternalBlacklist { get; init; }
}

public sealed class BlockedIpInfo
{
    public required string IpAddress { get; init; }
    public DateTime ExpiresAt { get; init; }
    public int RemainingMinutes { get; init; }
}
