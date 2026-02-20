using System.Collections.Concurrent;
using System.Net;
using CnCNetServer.Configuration;
using Serilog;

namespace CnCNetServer.Security;

/// <summary>
/// Manages IP-based security including rate limiting, blacklisting, and DDoS protection.
/// Thread-safe for concurrent access from multiple tunnel handlers.
/// </summary>
public sealed class IpSecurityManager : IDisposable
{
    private readonly ILogger _logger;
    private readonly SecurityOptions _options;
    private readonly Timer _cleanupTimer;
    private readonly Timer _blacklistRefreshTimer;

    // Rate limiting: tracks request counts per IP (key = IP string, avoids hash collisions)
    private readonly ConcurrentDictionary<string, RateLimitEntry> _rateLimits = new();

    // Local blacklist: IPs that exceeded limits (key = IP string)
    private readonly ConcurrentDictionary<string, DateTime> _localBlacklist = new();

    // External blacklists: swapped atomically on each refresh
    private volatile ConcurrentDictionary<string, bool> _externalBlacklist = new();
    private volatile List<(uint Network, uint Mask)> _networkBlacklist = [];

    // Lock only for network blacklist reads during refresh swap
    private readonly ReaderWriterLockSlim _networkLock = new();

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
    {
        Interlocked.Increment(ref _totalConnections);
        var ipKey = address.ToString();

        // Check local blacklist
        if (_localBlacklist.TryGetValue(ipKey, out var expiry))
        {
            if (DateTime.UtcNow < expiry)
            {
                Interlocked.Increment(ref _blockedByLocalBlacklist);
                return false;
            }
            _localBlacklist.TryRemove(ipKey, out _);
        }

        // Check external blacklist (snapshot - safe for concurrent reads)
        var externalBlacklist = _externalBlacklist;
        if (externalBlacklist.ContainsKey(ipKey))
        {
            Interlocked.Increment(ref _blockedByExternalBlacklist);
            return false;
        }

        // Check CIDR network blacklist
        if (IsInNetworkBlacklist(address))
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
    {
        if (_rateLimits.Count >= maxGlobal)
            return false;

        var entry = _rateLimits.GetOrAdd(address.ToString(), _ => new RateLimitEntry());
        return entry.IncrementPingCount() <= maxPerIp;
    }

    /// <summary>
    /// Tracks a connection for rate limiting purposes.
    /// </summary>
    public bool TrackConnection(IPAddress address, int maxConnectionsPerIp)
    {
        var entry = _rateLimits.GetOrAdd(address.ToString(), _ => new RateLimitEntry());
        return entry.IncrementConnectionCount() <= maxConnectionsPerIp;
    }

    /// <summary>
    /// Decrements the connection count for an IP when a client disconnects.
    /// </summary>
    public void ReleaseConnection(IPAddress address)
    {
        if (_rateLimits.TryGetValue(address.ToString(), out var entry))
            entry.DecrementConnectionCount();
    }

    /// <summary>
    /// Adds an IP to the local blacklist.
    /// </summary>
    public void AddToBlacklist(IPAddress address)
    {
        var expiry = DateTime.UtcNow.AddHours(_options.IpBlacklistDurationHours);
        _localBlacklist[address.ToString()] = expiry;
        _logger.Warning("IP {IP} added to local blacklist until {Expiry}", address, expiry);
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
                IpAddress = kvp.Key,
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
        if (!IPAddress.TryParse(ipAddress, out _))
            return false;

        var removed = _localBlacklist.TryRemove(ipAddress, out _);
        if (removed)
            _logger.Warning("IP {IP} manually removed from local blacklist", ipAddress);
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
        return new SecurityStatistics
        {
            TrackedIps = _rateLimits.Count,
            LocalBlacklistCount = _localBlacklist.Count,
            ExternalBlacklistCount = _externalBlacklist.Count + GetNetworkBlacklistCount(),
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

        // Build new collections – old ones remain fully active during refresh
        var newExternalBlacklist = new ConcurrentDictionary<string, bool>();
        var newNetworkBlacklist = new List<(uint Network, uint Mask)>();

        var totalIps = 0;
        var totalNetworks = 0;
        var successfulSources = 0;

        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        foreach (var url in _options.ExternalBlacklistUrls)
        {
            try
            {
                var content = await httpClient.GetStringAsync(url);
                var (ips, networks) = ParseBlacklist(content, newExternalBlacklist, newNetworkBlacklist);
                totalIps += ips;
                totalNetworks += networks;
                successfulSources++;
            }
            catch (Exception ex)
            {
                _logger.Warning("Failed to load blacklist from {Url}: {Error}", url, ex.Message);
            }
        }

        // Atomic swap – readers instantly see the new complete list
        _networkLock.EnterWriteLock();
        try
        {
            _externalBlacklist = newExternalBlacklist;
            _networkBlacklist = newNetworkBlacklist;
        }
        finally
        {
            _networkLock.ExitWriteLock();
        }

        _logger.Information(
            "External blacklist loaded: {IpCount} IPs, {NetworkCount} networks from {Success}/{Total} sources",
            totalIps, totalNetworks, successfulSources, _options.ExternalBlacklistUrls.Length);
    }

    private static (int ips, int networks) ParseBlacklist(
        string content,
        ConcurrentDictionary<string, bool> ipDict,
        List<(uint, uint)> networkList)
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
                if (TryParseCidr(trimmed, out var network, out var mask))
                {
                    networkList.Add((network, mask));
                    networks++;
                }
            }
            else if (IPAddress.TryParse(trimmed, out var address))
            {
                ipDict[address.ToString()] = true;
                ips++;
            }
        }

        return (ips, networks);
    }

    private static bool TryParseCidr(string cidr, out uint network, out uint mask)
    {
        network = 0;
        mask = 0;

        var parts = cidr.Split('/');
        if (parts.Length != 2) return false;

        if (!IPAddress.TryParse(parts[0], out var address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        if (!int.TryParse(parts[1], out var prefixLength) || prefixLength < 0 || prefixLength > 32)
            return false;

        var bytes = address.GetAddressBytes();
        network = (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
        mask = prefixLength == 0 ? 0 : uint.MaxValue << (32 - prefixLength);
        return true;
    }

    private bool IsInNetworkBlacklist(IPAddress address)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        var bytes = address.GetAddressBytes();
        var ip = (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);

        // Read snapshot – the list reference is volatile, no lock needed for reads
        var networkBlacklist = _networkBlacklist;
        foreach (var (network, mask) in networkBlacklist)
        {
            if ((ip & mask) == (network & mask))
                return true;
        }
        return false;
    }

    private int GetNetworkBlacklistCount() => _networkBlacklist.Count;

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
            if (kvp.Value.LastActivity < cutoff && kvp.Value.ConnectionCount == 0)
                _rateLimits.TryRemove(kvp.Key, out _);
        }
    }

    public void Dispose()
    {
        _cleanupTimer.Dispose();
        _blacklistRefreshTimer.Dispose();
        _networkLock.Dispose();
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
    public void DecrementConnectionCount() => Interlocked.Decrement(ref _connectionCount);
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
