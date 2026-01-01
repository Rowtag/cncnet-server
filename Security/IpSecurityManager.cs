using System.Collections.Concurrent;
using System.Net;
using CnCNetServer.Configuration;
using CnCNetServer.Diagnostics;
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

    // Rate limiting: tracks request counts per IP
    private readonly ConcurrentDictionary<int, RateLimitEntry> _rateLimits = new();

    // Local blacklist: IPs that exceeded limits (hash -> (expiry, original IP string))
    private readonly ConcurrentDictionary<int, (DateTime Expiry, string IpAddress)> _localBlacklist = new();

    // External blacklist: IPs loaded from external sources
    private readonly ConcurrentDictionary<int, bool> _externalBlacklist = new();

    // CIDR network blacklist for external sources
    private readonly List<(uint Network, uint Mask)> _networkBlacklist = [];
    private readonly ReaderWriterLockSlim _networkLock = new();

    // Known-good IP cache: IPs that passed blacklist check (cleared on blacklist refresh)
    // PERFORMANCE: Avoids repeated O(n) blacklist iterations for returning IPs
    private readonly ConcurrentDictionary<int, bool> _knownGoodIps = new();
    private const int MaxKnownGoodIps = 50000;

    // Statistics
    private long _totalConnections;
    private long _blockedByLocalBlacklist;
    private long _blockedByExternalBlacklist;

    /// <summary>
    /// Interval for cleanup of expired rate limit entries.
    /// </summary>
    private const int CleanupIntervalSeconds = 60;

    /// <summary>
    /// Interval for refreshing external blacklists.
    /// </summary>
    private const int BlacklistRefreshIntervalHours = 1;

    /// <summary>
    /// Maximum number of tracked IPs to prevent memory exhaustion.
    /// </summary>
    private const int MaxTrackedIps = 10000;

    /// <summary>
    /// Maximum number of local blacklist entries.
    /// </summary>
    private const int MaxLocalBlacklistEntries = 1000;

    /// <summary>
    /// Maximum number of external blacklist IPs to prevent memory exhaustion.
    /// </summary>
    private const int MaxExternalBlacklistIps = 100000;

    /// <summary>
    /// Maximum number of external blacklist networks (CIDR ranges).
    /// </summary>
    private const int MaxExternalBlacklistNetworks = 10000;

    public IpSecurityManager(SecurityOptions options, ILogger logger)
    {
        _options = options;
        _logger = logger.ForContext<IpSecurityManager>();

        // Start cleanup timer for expired entries
        _cleanupTimer = new Timer(
            CleanupExpiredEntries,
            null,
            TimeSpan.FromSeconds(CleanupIntervalSeconds),
            TimeSpan.FromSeconds(CleanupIntervalSeconds));

        // Start external blacklist refresh timer
        _blacklistRefreshTimer = new Timer(
            async _ => await RefreshExternalBlacklistsAsync(),
            null,
            TimeSpan.Zero, // Start immediately
            TimeSpan.FromHours(BlacklistRefreshIntervalHours));
    }

    /// <summary>
    /// Checks if an IP address is allowed to connect (not blacklisted).
    /// PERFORMANCE: Uses known-good cache to avoid repeated O(n) blacklist iterations.
    /// </summary>
    /// <param name="address">The IP address to check.</param>
    /// <returns>True if allowed, false if blocked.</returns>
    public bool IsConnectionAllowed(IPAddress address)
    {
        Interlocked.Increment(ref _totalConnections);
        var ipHash = address.GetHashCode();

        // Check local blacklist first (fastest check, always checked - can change at runtime)
        if (_localBlacklist.TryGetValue(ipHash, out var entry))
        {
            if (DateTime.UtcNow < entry.Expiry)
            {
                Interlocked.Increment(ref _blockedByLocalBlacklist);
                ConnectionTracer.Instance.LogEvent(address, TraceEventType.BlockedByLocalBlacklist,
                    $"Blocked until {entry.Expiry:HH:mm:ss}");
                return false;
            }
            // Entry expired, remove it
            _localBlacklist.TryRemove(ipHash, out _);
        }

        // PERFORMANCE: Check known-good cache before expensive blacklist lookups
        // This avoids O(n) CIDR iteration for returning IPs
        if (_knownGoodIps.ContainsKey(ipHash))
        {
            return true;
        }

        // Check external blacklist (IP hash lookup - O(1))
        if (_externalBlacklist.ContainsKey(ipHash))
        {
            Interlocked.Increment(ref _blockedByExternalBlacklist);
            ConnectionTracer.Instance.LogEvent(address, TraceEventType.BlockedByExternalBlacklist,
                "Blocked by external IP blacklist");
            return false;
        }

        // Check network blacklist (CIDR ranges - O(n) iteration)
        if (IsInNetworkBlacklist(address))
        {
            Interlocked.Increment(ref _blockedByExternalBlacklist);
            ConnectionTracer.Instance.LogEvent(address, TraceEventType.BlockedByExternalBlacklist,
                "Blocked by external CIDR blacklist");
            return false;
        }

        // IP passed all checks - add to known-good cache
        if (_knownGoodIps.Count < MaxKnownGoodIps)
        {
            _knownGoodIps.TryAdd(ipHash, true);
        }

        return true;
    }

    /// <summary>
    /// Checks if a ping request from an IP is within rate limits.
    /// </summary>
    /// <param name="address">The IP address.</param>
    /// <param name="maxPerIp">Maximum pings allowed per IP per interval.</param>
    /// <param name="maxGlobal">Maximum total pings allowed globally per interval.</param>
    /// <returns>True if within limits, false if rate limit exceeded.</returns>
    public bool IsPingAllowed(IPAddress address, int maxPerIp, int maxGlobal)
    {
        // Check global limit first
        if (_rateLimits.Count >= maxGlobal)
            return false;

        // Prevent memory exhaustion - reject if too many IPs tracked
        if (_rateLimits.Count >= MaxTrackedIps)
            return false;

        var ipHash = address.GetHashCode();
        var entry = _rateLimits.GetOrAdd(ipHash, _ => new RateLimitEntry());

        var count = entry.IncrementPingCount();
        return count <= maxPerIp;
    }

    /// <summary>
    /// Tracks a connection for rate limiting purposes.
    /// </summary>
    /// <param name="address">The IP address to track.</param>
    /// <param name="maxConnectionsPerIp">Maximum connections allowed per IP.</param>
    /// <returns>True if connection is allowed, false if limit exceeded.</returns>
    public bool TrackConnection(IPAddress address, int maxConnectionsPerIp)
    {
        // Prevent memory exhaustion - reject if too many IPs tracked
        if (_rateLimits.Count >= MaxTrackedIps)
            return false;

        var ipHash = address.GetHashCode();
        var entry = _rateLimits.GetOrAdd(ipHash, _ => new RateLimitEntry());

        var count = entry.IncrementConnectionCount();
        return count <= maxConnectionsPerIp;
    }

    /// <summary>
    /// Decrements the connection count for an IP when a client disconnects.
    /// </summary>
    public void ReleaseConnection(IPAddress address)
    {
        var ipHash = address.GetHashCode();
        if (_rateLimits.TryGetValue(ipHash, out var entry))
        {
            entry.DecrementConnectionCount();
        }
    }

    /// <summary>
    /// Adds an IP to the local blacklist.
    /// </summary>
    /// <param name="address">The IP address to blacklist.</param>
    public void AddToBlacklist(IPAddress address)
    {
        // Prevent memory exhaustion - don't add if at limit
        if (_localBlacklist.Count >= MaxLocalBlacklistEntries)
        {
            _logger.Warning("Local blacklist at capacity ({Max}), cannot add IP {IP}", MaxLocalBlacklistEntries, IpAnonymizer.Anonymize(address));
            return;
        }

        var ipHash = address.GetHashCode();
        var expiry = DateTime.UtcNow.AddHours(_options.IpBlacklistDurationHours);
        _localBlacklist[ipHash] = (expiry, address.ToString());
        _logger.Warning("IP {IP} added to local blacklist until {Expiry}", IpAnonymizer.Anonymize(address), expiry);

        ConnectionTracer.Instance.LogEvent(address, TraceEventType.AddedToBlacklist,
            $"Added to local blacklist for {_options.IpBlacklistDurationHours}h");
    }

    /// <summary>
    /// Gets all currently blocked IPs from the local blacklist.
    /// </summary>
    public IEnumerable<BlockedIpInfo> GetBlockedIps()
    {
        var now = DateTime.UtcNow;
        return _localBlacklist
            .Where(kvp => kvp.Value.Expiry > now)
            .Select(kvp => new BlockedIpInfo
            {
                IpAddress = kvp.Value.IpAddress,
                ExpiresAt = kvp.Value.Expiry,
                RemainingMinutes = (int)(kvp.Value.Expiry - now).TotalMinutes
            })
            .OrderByDescending(x => x.RemainingMinutes);
    }

    /// <summary>
    /// Removes an IP from the local blacklist.
    /// </summary>
    public bool RemoveFromBlacklist(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var address))
            return false;

        var ipHash = address.GetHashCode();
        var removed = _localBlacklist.TryRemove(ipHash, out _);
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
        {
            entry.ResetPingCount();
        }
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
    /// PERFORMANCE: Clears known-good cache to ensure new blacklist entries take effect.
    /// </summary>
    public async Task RefreshExternalBlacklistsAsync()
    {
        if (_options.ExternalBlacklistUrls.Length == 0)
            return;

        _logger.Information("Refreshing external IP blacklists...");

        // PERFORMANCE: Clear known-good cache so IPs are re-checked against new blacklist
        var cachedCount = _knownGoodIps.Count;
        _knownGoodIps.Clear();

        var totalIps = 0;
        var totalNetworks = 0;
        var successfulSources = 0;

        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        foreach (var url in _options.ExternalBlacklistUrls)
        {
            try
            {
                var content = await httpClient.GetStringAsync(url);
                var (ips, networks) = ParseBlacklist(content);
                totalIps += ips;
                totalNetworks += networks;
                successfulSources++;
            }
            catch (Exception ex)
            {
                _logger.Warning("Failed to load blacklist from {Url}: {Error}", url, ex.Message);
            }
        }

        _logger.Information(
            "External blacklist loaded: {IpCount} IPs, {NetworkCount} networks from {Success}/{Total} sources (cleared {CacheCount} cached IPs)",
            totalIps, totalNetworks, successfulSources, _options.ExternalBlacklistUrls.Length, cachedCount);
    }

    /// <summary>
    /// Parses a blacklist file content and adds entries to the blacklist.
    /// Supports individual IPs and CIDR notation.
    /// </summary>
    private (int ips, int networks) ParseBlacklist(string content)
    {
        var ips = 0;
        var networks = 0;

        foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();

            // Skip comments and empty lines
            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#') || trimmed.StartsWith(';'))
                continue;

            // Check if it's a CIDR range
            if (trimmed.Contains('/'))
            {
                // Limit check for networks
                if (networks >= MaxExternalBlacklistNetworks)
                    continue;

                if (TryParseCidr(trimmed, out var network, out var mask))
                {
                    _networkLock.EnterWriteLock();
                    try
                    {
                        _networkBlacklist.Add((network, mask));
                    }
                    finally
                    {
                        _networkLock.ExitWriteLock();
                    }
                    networks++;
                }
            }
            else if (IPAddress.TryParse(trimmed, out var address))
            {
                // Limit check for IPs
                if (ips >= MaxExternalBlacklistIps)
                    continue;

                _externalBlacklist[address.GetHashCode()] = true;
                ips++;
            }
        }

        return (ips, networks);
    }

    /// <summary>
    /// Parses a CIDR notation string into network and mask.
    /// </summary>
    private static bool TryParseCidr(string cidr, out uint network, out uint mask)
    {
        network = 0;
        mask = 0;

        var parts = cidr.Split('/');
        if (parts.Length != 2)
            return false;

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

    /// <summary>
    /// Checks if an IP address is within any blacklisted network range.
    /// PERFORMANCE: Early exit if no networks are blacklisted.
    /// </summary>
    private bool IsInNetworkBlacklist(IPAddress address)
    {
        // PERFORMANCE: Quick check without lock - most common case
        if (_networkBlacklist.Count == 0)
            return false;

        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        var bytes = address.GetAddressBytes();
        var ip = (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);

        _networkLock.EnterReadLock();
        try
        {
            foreach (var (network, mask) in _networkBlacklist)
            {
                if ((ip & mask) == (network & mask))
                    return true;
            }
        }
        finally
        {
            _networkLock.ExitReadLock();
        }

        return false;
    }

    private int GetNetworkBlacklistCount()
    {
        _networkLock.EnterReadLock();
        try
        {
            return _networkBlacklist.Count;
        }
        finally
        {
            _networkLock.ExitReadLock();
        }
    }

    /// <summary>
    /// Cleans up expired rate limit and blacklist entries.
    /// </summary>
    private void CleanupExpiredEntries(object? state)
    {
        var now = DateTime.UtcNow;

        // Clean up expired local blacklist entries
        foreach (var kvp in _localBlacklist)
        {
            if (now >= kvp.Value.Expiry)
            {
                _localBlacklist.TryRemove(kvp.Key, out _);
            }
        }

        // Clean up inactive rate limit entries (no activity in last 5 minutes)
        var cutoff = now.AddMinutes(-5);
        foreach (var kvp in _rateLimits)
        {
            if (kvp.Value.LastActivity < cutoff && kvp.Value.ConnectionCount == 0)
            {
                _rateLimits.TryRemove(kvp.Key, out _);
            }
        }
    }

    public void Dispose()
    {
        _cleanupTimer.Dispose();
        _blacklistRefreshTimer.Dispose();
        _networkLock.Dispose();
    }
}

/// <summary>
/// Tracks rate limiting state for a single IP address.
/// </summary>
internal sealed class RateLimitEntry
{
    private int _pingCount;
    private int _connectionCount;

    public DateTime LastActivity { get; private set; } = DateTime.UtcNow;
    public int ConnectionCount => Volatile.Read(ref _connectionCount);

    public int IncrementPingCount()
    {
        LastActivity = DateTime.UtcNow;
        return Interlocked.Increment(ref _pingCount);
    }

    public void ResetPingCount()
    {
        Interlocked.Exchange(ref _pingCount, 0);
    }

    public int IncrementConnectionCount()
    {
        LastActivity = DateTime.UtcNow;
        return Interlocked.Increment(ref _connectionCount);
    }

    public void DecrementConnectionCount()
    {
        Interlocked.Decrement(ref _connectionCount);
    }
}

/// <summary>
/// Security statistics for monitoring.
/// </summary>
public sealed class SecurityStatistics
{
    public int TrackedIps { get; init; }
    public int LocalBlacklistCount { get; init; }
    public int ExternalBlacklistCount { get; init; }
    public long TotalConnections { get; init; }
    public long BlockedByLocalBlacklist { get; init; }
    public long BlockedByExternalBlacklist { get; init; }
}

/// <summary>
/// Information about a blocked IP address.
/// </summary>
public sealed class BlockedIpInfo
{
    public required string IpAddress { get; init; }
    public DateTime ExpiresAt { get; init; }
    public int RemainingMinutes { get; init; }
}
