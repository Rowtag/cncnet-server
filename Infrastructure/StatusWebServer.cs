using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;
using CnCNetServer.Configuration;
using CnCNetServer.Diagnostics;
using CnCNetServer.Logging;
using CnCNetServer.Security;
using CnCNetServer.Tunnels;
using Serilog;
using SysProcess = System.Diagnostics.Process;

namespace CnCNetServer.Infrastructure;

/// <summary>
/// Web-based monitoring dashboard for the CnCNet tunnel server.
/// Protected by login with brute-force protection.
/// </summary>
public sealed class StatusWebServer : IDisposable
{
    private readonly HttpListener _listener;
    private readonly ILogger _logger;
    private readonly ServiceOptions _options;
    private readonly DateTime _startTime;
    private readonly CancellationTokenSource _cts = new();

    // Service references for statistics
    private readonly TunnelV3? _tunnelV3;
    private readonly TunnelV2? _tunnelV2;
    private readonly IpSecurityManager _securityManager;

    // Brute-force protection: IP -> (failedAttempts, lockoutUntil)
    private readonly ConcurrentDictionary<string, (int Attempts, DateTime LockoutUntil)> _loginAttempts = new();
    private const int MaxLoginAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    // Session management
    private readonly ConcurrentDictionary<string, DateTime> _sessions = new();
    private static readonly TimeSpan SessionDuration = TimeSpan.FromHours(24);
    private const int MaxSessions = 100; // Prevent memory exhaustion from session creation
    private readonly Timer _cleanupTimer;

    // System monitoring (updated every minute)
    private readonly Timer _systemMonitorTimer;
    private readonly SysProcess _currentProcess;
    private double _cpuUsagePercent;
    private long _memoryUsageMB;
    private DateTime _lastCpuMeasurement;
    private TimeSpan _lastCpuTime;

    // Average session time (updated every 30 minutes using rolling average, persistent)
    private readonly Timer _sessionAvgTimer;
    private double _avgSessionMinutes;
    private readonly string _avgSessionFilePath;

    // Additional system metrics
    private long _totalMemoryMB;
    private long _logFileSizeKB;
    private long _freeDiskSpaceGB;


    public StatusWebServer(
        ServiceOptions options,
        IpSecurityManager securityManager,
        TunnelV3? tunnelV3,
        TunnelV2? tunnelV2,
        ILogger logger)
    {
        _options = options;
        _securityManager = securityManager;
        _tunnelV3 = tunnelV3;
        _tunnelV2 = tunnelV2;
        _logger = logger.ForContext<StatusWebServer>();
        _startTime = DateTime.UtcNow;

        _listener = new HttpListener();
        _listener.IgnoreWriteExceptions = true;

        // Setup cleanup timer for expired sessions and login attempts (every 5 minutes)
        _cleanupTimer = new Timer(CleanupExpiredData, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

        // Setup system monitoring timer (every 5 minutes - reduced from 1 min for CPU savings)
        // CPU/Memory/Disk metrics don't need frequent updates
        _currentProcess = SysProcess.GetCurrentProcess();
        _lastCpuMeasurement = DateTime.UtcNow;
        _lastCpuTime = _currentProcess.TotalProcessorTime;
        _systemMonitorTimer = new Timer(UpdateSystemMetrics, null, TimeSpan.Zero, TimeSpan.FromMinutes(5));

        // Setup average session time timer (every 30 minutes, persistent)
        _avgSessionFilePath = Path.Combine(AppContext.BaseDirectory, "avg_session.dat");
        LoadAverageSessionTime();
        _sessionAvgTimer = new Timer(UpdateSessionAverages, null, TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(30));
    }

    /// <summary>
    /// Loads the average session time from persistent storage.
    /// </summary>
    private void LoadAverageSessionTime()
    {
        try
        {
            if (File.Exists(_avgSessionFilePath))
            {
                var content = File.ReadAllText(_avgSessionFilePath);
                if (double.TryParse(content, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var value))
                {
                    _avgSessionMinutes = value;
                    _logger.Information("[WEB] Loaded persistent average session time: {Avg:F1} min", _avgSessionMinutes);
                }
            }
        }
        catch
        {
            // Ignore errors loading saved value
        }
    }

    /// <summary>
    /// Saves the average session time to persistent storage.
    /// </summary>
    private void SaveAverageSessionTime()
    {
        try
        {
            File.WriteAllText(_avgSessionFilePath,
                _avgSessionMinutes.ToString("F2", System.Globalization.CultureInfo.InvariantCulture));
        }
        catch
        {
            // Ignore errors saving value
        }
    }

    /// <summary>
    /// Updates CPU and memory usage metrics.
    /// </summary>
    private void UpdateSystemMetrics(object? state)
    {
        try
        {
            _currentProcess.Refresh();

            // Calculate CPU usage
            var now = DateTime.UtcNow;
            var cpuTime = _currentProcess.TotalProcessorTime;
            var elapsed = now - _lastCpuMeasurement;

            if (elapsed.TotalMilliseconds > 0)
            {
                var cpuUsed = (cpuTime - _lastCpuTime).TotalMilliseconds;
                _cpuUsagePercent = (cpuUsed / elapsed.TotalMilliseconds / Environment.ProcessorCount) * 100;
            }

            _lastCpuMeasurement = now;
            _lastCpuTime = cpuTime;

            // Get memory usage
            _memoryUsageMB = _currentProcess.WorkingSet64 / 1024 / 1024;

            // Get total system memory (approximate from GC info)
            var gcInfo = GC.GetGCMemoryInfo();
            _totalMemoryMB = gcInfo.TotalAvailableMemoryBytes / 1024 / 1024;

            // Get log file size
            UpdateLogFileSize();

            // Get free disk space
            UpdateFreeDiskSpace();
        }
        catch
        {
            // Ignore errors in metrics collection
        }
    }

    /// <summary>
    /// Updates the free disk space metric.
    /// </summary>
    private void UpdateFreeDiskSpace()
    {
        try
        {
            var drive = new DriveInfo(Path.GetPathRoot(AppContext.BaseDirectory) ?? "C:");
            _freeDiskSpaceGB = drive.AvailableFreeSpace / 1024 / 1024 / 1024;
        }
        catch
        {
            // Ignore errors
        }
    }

    /// <summary>
    /// Updates the log file size metric.
    /// </summary>
    private void UpdateLogFileSize()
    {
        try
        {
            var logDir = Path.Combine(AppContext.BaseDirectory, _options.Logging.LogDirectory);
            if (Directory.Exists(logDir))
            {
                var totalSize = Directory.GetFiles(logDir, "*.log", SearchOption.TopDirectoryOnly)
                    .Sum(f => new FileInfo(f).Length);
                _logFileSizeKB = totalSize / 1024;
            }
        }
        catch
        {
            // Ignore errors
        }
    }

    /// <summary>
    /// Updates average session time using rolling average.
    /// Called every 30 minutes to calculate from recent session data.
    /// Formula: new_avg = (old_avg + current_snapshot_avg) / 2
    /// Combines V3 and V2 sessions and persists to file.
    /// </summary>
    private void UpdateSessionAverages(object? state)
    {
        try
        {
            // Get all completed sessions from both V3 and V2
            var allSessions = SessionLog.V3.GetEntries()
                .Concat(SessionLog.V2.GetEntries())
                .Where(s => s.Duration.HasValue)
                .ToList();

            if (allSessions.Count > 0)
            {
                var currentAvg = allSessions.Average(s => s.Duration!.Value.TotalMinutes);

                // Rolling average: blend with previous value
                _avgSessionMinutes = _avgSessionMinutes == 0
                    ? currentAvg
                    : (_avgSessionMinutes + currentAvg) / 2;

                // Persist to file
                SaveAverageSessionTime();

                _logger.Debug("[WEB] Session average updated: {Avg:F1}min (from {Count} sessions)",
                    _avgSessionMinutes, allSessions.Count);
            }
        }
        catch
        {
            // Ignore errors in metrics collection
        }
    }

    /// <summary>
    /// Cleans up expired sessions and login lockouts to prevent memory buildup.
    /// </summary>
    private void CleanupExpiredData(object? state)
    {
        var now = DateTime.UtcNow;
        var expiredSessionCount = 0;
        var expiredLockoutCount = 0;

        // Remove expired sessions
        foreach (var (sessionId, expiry) in _sessions)
        {
            if (now >= expiry && _sessions.TryRemove(sessionId, out _))
            {
                expiredSessionCount++;
            }
        }

        // Remove expired login lockouts
        foreach (var (ip, (_, lockoutUntil)) in _loginAttempts)
        {
            if (now >= lockoutUntil && _loginAttempts.TryRemove(ip, out _))
            {
                expiredLockoutCount++;
            }
        }

        if (expiredSessionCount > 0 || expiredLockoutCount > 0)
        {
            _logger.Debug("[WEB] Cleanup: removed {Sessions} expired sessions, {Lockouts} expired lockouts",
                expiredSessionCount, expiredLockoutCount);
        }
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);

        _listener.Prefixes.Add($"http://*:{_options.WebMonitor.Port}/");
        _listener.Start();
        _logger.Information("Web monitor running on port {Port} (all interfaces)", _options.WebMonitor.Port);

        while (!linkedCts.Token.IsCancellationRequested)
        {
            try
            {
                var context = await _listener.GetContextAsync().WaitAsync(linkedCts.Token);
                _ = ProcessRequestAsync(context);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (HttpListenerException ex) when (ex.ErrorCode == 995)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Web monitor error");
            }
        }
    }

    private async Task ProcessRequestAsync(HttpListenerContext context)
    {
        var response = context.Response;
        var request = context.Request;
        var path = request.Url?.AbsolutePath ?? "/";
        var clientIp = request.RemoteEndPoint?.Address.ToString() ?? "unknown";

        // Add security headers to all responses
        AddSecurityHeaders(response);

        try
        {
            // Check if login is required (password is set)
            var requiresAuth = !string.IsNullOrEmpty(_options.Maintenance.Password);

            // Handle login page and authentication
            if (path.Equals("/login", StringComparison.OrdinalIgnoreCase))
            {
                if (request.HttpMethod == "POST")
                {
                    await HandleLoginPostAsync(request, response, clientIp);
                }
                else
                {
                    await SendLoginPageAsync(response);
                }
                return;
            }

            if (path.Equals("/logout", StringComparison.OrdinalIgnoreCase))
            {
                HandleLogout(request, response);
                return;
            }

            // Check authentication for all other pages
            if (requiresAuth && !IsAuthenticated(request))
            {
                response.Redirect("/login");
                return;
            }

            // Handle API endpoints
            if (path.Equals("/json", StringComparison.OrdinalIgnoreCase))
            {
                await SendJsonResponseAsync(response);
            }
            else if (path.StartsWith("/maintenance/", StringComparison.OrdinalIgnoreCase))
            {
                HandleMaintenanceRequest(path, response);
            }
            else if (path.StartsWith("/toggle/", StringComparison.OrdinalIgnoreCase))
            {
                HandleToggleRequest(path, response);
            }
            else if (path.StartsWith("/setlimit/", StringComparison.OrdinalIgnoreCase))
            {
                HandleSetLimitRequest(path, response);
            }
            else if (path.StartsWith("/setblacklistduration/", StringComparison.OrdinalIgnoreCase))
            {
                HandleSetBlacklistDurationRequest(path, response);
            }
            else if (path.StartsWith("/unblock/", StringComparison.OrdinalIgnoreCase))
            {
                HandleUnblockRequest(path, response);
            }
            else if (path.StartsWith("/setloglevel/", StringComparison.OrdinalIgnoreCase))
            {
                HandleSetLogLevelRequest(path, response);
            }
            else if (path.StartsWith("/setloglimit/", StringComparison.OrdinalIgnoreCase))
            {
                HandleSetLogLimitRequest(path, response);
            }
            else if (path.StartsWith("/setsessionlimit/", StringComparison.OrdinalIgnoreCase))
            {
                HandleSetSessionLimitRequest(path, response);
            }
            else if (path.StartsWith("/setview/", StringComparison.OrdinalIgnoreCase))
            {
                HandleSetViewRequest(path, response);
            }
            else if (path.StartsWith("/setname/", StringComparison.OrdinalIgnoreCase))
            {
                HandleSetNameRequest(path, response);
            }
            // Trace endpoints - only available if --trace was set at startup
            else if (path.StartsWith("/trace/", StringComparison.OrdinalIgnoreCase))
            {
                if (!_options.Diagnostics.TraceAllConnections)
                {
                    response.StatusCode = 403; // Forbidden - trace not enabled
                }
                else if (path.StartsWith("/trace/start/", StringComparison.OrdinalIgnoreCase))
                {
                    HandleTraceStartRequest(path, response);
                }
                else if (path.StartsWith("/trace/stop/", StringComparison.OrdinalIgnoreCase))
                {
                    HandleTraceStopRequest(path, response);
                }
                else if (path.Equals("/trace/stopall", StringComparison.OrdinalIgnoreCase))
                {
                    HandleTraceStopAllRequest(response);
                }
                else if (path.Equals("/trace/all/on", StringComparison.OrdinalIgnoreCase))
                {
                    HandleTraceAllOnRequest(response);
                }
                else if (path.Equals("/trace/all/off", StringComparison.OrdinalIgnoreCase))
                {
                    HandleTraceAllOffRequest(response);
                }
                else if (path.Equals("/trace/all/important", StringComparison.OrdinalIgnoreCase))
                {
                    HandleTraceAllImportantRequest(response);
                }
                else if (path.StartsWith("/trace/level/", StringComparison.OrdinalIgnoreCase))
                {
                    HandleSetTraceLevelRequest(path, response);
                }
                else
                {
                    response.StatusCode = 404;
                }
            }
            else
            {
                await SendHtmlResponseAsync(response, requiresAuth);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning("Request error: {Error}", ex.Message);
        }
        finally
        {
            try { response.Close(); } catch { }
        }
    }

    #region Security

    /// <summary>
    /// Adds security headers to prevent common web vulnerabilities.
    /// </summary>
    private static void AddSecurityHeaders(HttpListenerResponse response)
    {
        // Prevent clickjacking attacks
        response.Headers.Add("X-Frame-Options", "DENY");

        // Prevent MIME type sniffing
        response.Headers.Add("X-Content-Type-Options", "nosniff");

        // Enable XSS filter in older browsers
        response.Headers.Add("X-XSS-Protection", "1; mode=block");

        // Content Security Policy - restrict resources to same origin
        response.Headers.Add("Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'");

        // Referrer policy - don't leak referrer information
        response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");

        // Permissions policy - disable unnecessary browser features
        response.Headers.Add("Permissions-Policy", "geolocation=(), microphone=(), camera=()");

        // Cache control for security-sensitive pages
        response.Headers.Add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.Headers.Add("Pragma", "no-cache");
    }

    /// <summary>
    /// Sets a secure session cookie with HttpOnly, SameSite, and optional Secure flags.
    /// </summary>
    private static void SetSecureSessionCookie(HttpListenerResponse response, string sessionId, bool isHttps = false)
    {
        // Build cookie with security flags
        // Note: Secure flag requires HTTPS - we set it based on connection type
        var cookieValue = $"session={sessionId}; Path=/; HttpOnly; SameSite=Strict";
        if (isHttps)
        {
            cookieValue += "; Secure";
        }
        response.Headers.Add("Set-Cookie", cookieValue);
    }

    /// <summary>
    /// Clears the session cookie securely.
    /// </summary>
    private static void ClearSessionCookie(HttpListenerResponse response)
    {
        response.Headers.Add("Set-Cookie", "session=; Path=/; HttpOnly; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #endregion

    #region Authentication

    private bool IsAuthenticated(HttpListenerRequest request)
    {
        var cookie = request.Cookies["session"];
        if (cookie == null || string.IsNullOrEmpty(cookie.Value))
            return false;

        if (_sessions.TryGetValue(cookie.Value, out var expiry))
        {
            if (DateTime.UtcNow < expiry)
                return true;
            _sessions.TryRemove(cookie.Value, out _);
        }
        return false;
    }

    private async Task HandleLoginPostAsync(HttpListenerRequest request, HttpListenerResponse response, string clientIp)
    {
        // Check brute-force lockout
        if (_loginAttempts.TryGetValue(clientIp, out var attempt) && DateTime.UtcNow < attempt.LockoutUntil)
        {
            var remaining = (int)(attempt.LockoutUntil - DateTime.UtcNow).TotalMinutes;
            await SendLoginPageAsync(response, $"Too many failed attempts. Try again in {remaining} minutes.");
            return;
        }

        // Validate Content-Type
        if (request.ContentType == null || !request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            response.StatusCode = 415; // Unsupported Media Type
            return;
        }

        // Limit POST body size (1KB is more than enough for password)
        const int maxBodySize = 1024;
        if (request.ContentLength64 > maxBodySize)
        {
            response.StatusCode = 413; // Payload Too Large
            return;
        }

        // Read POST body with size limit
        using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        var buffer = new char[maxBodySize];
        var bytesRead = await reader.ReadAsync(buffer, 0, maxBodySize);
        var body = new string(buffer, 0, bytesRead);
        var formData = HttpUtility.ParseQueryString(body);
        var password = formData["password"];

        // Use constant-time comparison to prevent timing attacks
        var isValidPassword = !string.IsNullOrEmpty(password) &&
                              !string.IsNullOrEmpty(_options.Maintenance.Password) &&
                              CryptographicOperations.FixedTimeEquals(
                                  Encoding.UTF8.GetBytes(password),
                                  Encoding.UTF8.GetBytes(_options.Maintenance.Password));

        if (isValidPassword)
        {
            // Check session limit to prevent memory exhaustion
            if (_sessions.Count >= MaxSessions)
            {
                // Remove 10% of oldest sessions to make room and avoid frequent cleanup
                var sessionsToRemove = Math.Max(10, MaxSessions / 10);
                var oldestSessions = _sessions
                    .OrderBy(s => s.Value)
                    .Take(sessionsToRemove)
                    .Select(s => s.Key)
                    .ToList();

                foreach (var oldSession in oldestSessions)
                {
                    _sessions.TryRemove(oldSession, out _);
                }

                _logger.Debug("[WEB] Session limit reached, removed {Count} oldest sessions", sessionsToRemove);
            }

            // Successful login - create session
            var sessionId = Guid.NewGuid().ToString("N");
            _sessions[sessionId] = DateTime.UtcNow.Add(SessionDuration);

            // Clear failed attempts
            _loginAttempts.TryRemove(clientIp, out _);

            // Set secure session cookie
            var isHttps = request.IsSecureConnection;
            SetSecureSessionCookie(response, sessionId, isHttps);

            _logger.Information("[WEB] Successful login from {IP}", IpAnonymizer.Anonymize(clientIp));

            response.Redirect("/");
        }
        else
        {
            // Failed login - track attempts
            var currentAttempts = _loginAttempts.AddOrUpdate(
                clientIp,
                _ => (1, DateTime.MinValue),
                (_, existing) => (existing.Attempts + 1, existing.LockoutUntil));

            if (currentAttempts.Attempts >= MaxLoginAttempts)
            {
                _loginAttempts[clientIp] = (currentAttempts.Attempts, DateTime.UtcNow.Add(LockoutDuration));
                _logger.Warning("[WEB] IP {IP} locked out after {Attempts} failed login attempts", IpAnonymizer.Anonymize(clientIp), currentAttempts.Attempts);
                await SendLoginPageAsync(response, $"Too many failed attempts. Locked out for {LockoutDuration.TotalMinutes} minutes.");
            }
            else
            {
                _logger.Warning("[WEB] Failed login attempt from {IP} ({Attempts}/{Max})", IpAnonymizer.Anonymize(clientIp), currentAttempts.Attempts, MaxLoginAttempts);
                await SendLoginPageAsync(response, $"Invalid password. {MaxLoginAttempts - currentAttempts.Attempts} attempts remaining.");
            }
        }
    }

    private void HandleLogout(HttpListenerRequest request, HttpListenerResponse response)
    {
        var cookie = request.Cookies["session"];
        if (cookie != null && !string.IsNullOrEmpty(cookie.Value))
        {
            _sessions.TryRemove(cookie.Value, out _);
        }

        // Clear cookie securely
        ClearSessionCookie(response);
        response.Redirect("/login");
    }

    private async Task SendLoginPageAsync(HttpListenerResponse response, string? error = null)
    {
        var errorHtml = string.IsNullOrEmpty(error)
            ? ""
            : $"<div class=\"error\">{HttpUtility.HtmlEncode(error)}</div>";

        var html = $$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>CnCNet Tunnel Server - Login</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background: #1a1a2e;
                        color: #eee;
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    .login-box {
                        background: #16213e;
                        border-radius: 12px;
                        padding: 40px;
                        border: 1px solid #0f3460;
                        width: 100%;
                        max-width: 400px;
                    }
                    h1 {
                        color: #00d4ff;
                        font-size: 1.5rem;
                        margin-bottom: 10px;
                        text-align: center;
                    }
                    .info {
                        color: #888;
                        font-size: 0.85rem;
                        text-align: center;
                        margin-bottom: 25px;
                    }
                    .error {
                        background: #ff444433;
                        border: 1px solid #ff4444;
                        color: #ff6666;
                        padding: 10px;
                        border-radius: 6px;
                        margin-bottom: 20px;
                        font-size: 0.9rem;
                    }
                    label {
                        display: block;
                        color: #888;
                        margin-bottom: 8px;
                    }
                    input[type="password"] {
                        width: 100%;
                        padding: 12px;
                        border: 1px solid #0f3460;
                        border-radius: 6px;
                        background: #1a1a2e;
                        color: #eee;
                        font-size: 16px;
                        margin-bottom: 20px;
                    }
                    input[type="password"]:focus {
                        outline: none;
                        border-color: #00d4ff;
                    }
                    button {
                        width: 100%;
                        padding: 12px;
                        background: #00d4ff;
                        color: #1a1a2e;
                        border: none;
                        border-radius: 6px;
                        font-size: 16px;
                        font-weight: 600;
                        cursor: pointer;
                    }
                    button:hover {
                        background: #00a8cc;
                    }
                    .hint {
                        color: #666;
                        font-size: 0.75rem;
                        text-align: center;
                        margin-top: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="login-box">
                    <h1>CnCNet Tunnel Server</h1>
                    <div class="info">Use the Maintenance Password to login</div>
                    {{errorHtml}}
                    <form method="POST" action="/login">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required autofocus>
                        <button type="submit">Login</button>
                    </form>
                    <div class="hint">--maintpw parameter required</div>
                </div>
            </body>
            </html>
            """;

        var buffer = Encoding.UTF8.GetBytes(html);
        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength64 = buffer.Length;
        await response.OutputStream.WriteAsync(buffer);
    }

    #endregion

    #region Request Handlers

    private void HandleMaintenanceRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            response.StatusCode = 400;
            return;
        }

        var target = parts[1].ToLowerInvariant();

        switch (target)
        {
            case "v3":
                _tunnelV3?.ToggleMaintenanceMode();
                var v3Status = _tunnelV3?.IsMaintenanceMode == true ? "ENABLED" : "DISABLED";
                _logger.Warning("[WEB] V3 Maintenance mode {Status}", v3Status);
                break;
            case "v2":
                _tunnelV2?.ToggleMaintenanceMode();
                var v2Status = _tunnelV2?.IsMaintenanceMode == true ? "ENABLED" : "DISABLED";
                _logger.Warning("[WEB] V2 Maintenance mode {Status}", v2Status);
                break;
            default:
                response.StatusCode = 400;
                return;
        }

        response.StatusCode = 200;
    }

    private void HandleToggleRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            response.StatusCode = 400;
            return;
        }

        var option = parts[1].ToLowerInvariant();

        switch (option)
        {
            case "v3validation":
                TunnelV3PacketValidation.Enabled = !TunnelV3PacketValidation.Enabled;
                _logger.Warning("[WEB] V3 Packet Validation {Status}", TunnelV3PacketValidation.Enabled ? "ENABLED" : "DISABLED");
                break;
            case "v3ddos":
                _options.TunnelV3.DDoSProtectionEnabled = !_options.TunnelV3.DDoSProtectionEnabled;
                _logger.Warning("[WEB] V3 DDoS Protection {Status}", _options.TunnelV3.DDoSProtectionEnabled ? "ENABLED" : "DISABLED");
                break;
            case "v2ddos":
                _options.TunnelV2.DDoSProtectionEnabled = !_options.TunnelV2.DDoSProtectionEnabled;
                _logger.Warning("[WEB] V2 DDoS Protection {Status}", _options.TunnelV2.DDoSProtectionEnabled ? "ENABLED" : "DISABLED");
                break;
            default:
                response.StatusCode = 400;
                return;
        }

        response.StatusCode = 200;
    }

    private void HandleSetLimitRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            response.StatusCode = 400;
            return;
        }

        var tunnel = parts[1].ToLowerInvariant();
        if (!int.TryParse(parts[2], out var value) || value < 1 || value > 40)
        {
            response.StatusCode = 400;
            return;
        }

        switch (tunnel)
        {
            case "v3":
                _options.TunnelV3.IpLimit = value;
                _logger.Warning("[WEB] V3 IP Limit changed to {Value}", value);
                break;
            case "v2":
                _options.TunnelV2.IpLimit = value;
                _logger.Warning("[WEB] V2 IP Limit changed to {Value}", value);
                break;
            default:
                response.StatusCode = 400;
                return;
        }

        response.StatusCode = 200;
    }

    private void HandleSetBlacklistDurationRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            response.StatusCode = 400;
            return;
        }

        if (!int.TryParse(parts[1], out var hours) || hours < 1 || hours > 168)
        {
            response.StatusCode = 400;
            return;
        }

        _options.Security.IpBlacklistDurationHours = hours;
        _logger.Warning("[WEB] Blacklist duration changed to {Hours} hours", hours);
        response.StatusCode = 200;
    }

    private void HandleUnblockRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            response.StatusCode = 400;
            return;
        }

        var ip = HttpUtility.UrlDecode(parts[1]);
        if (_securityManager.RemoveFromBlacklist(ip))
        {
            response.StatusCode = 200;
        }
        else
        {
            response.StatusCode = 404;
        }
    }

    private void HandleSetLogLevelRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var levelValue))
        {
            response.StatusCode = 400;
            return;
        }

        // Validate level is in valid range (0=Verbose to 4=Error)
        if (levelValue < 0 || levelValue > 4)
        {
            response.StatusCode = 400;
            return;
        }

        InMemoryLogSink.Instance.DisplayLevel = (Serilog.Events.LogEventLevel)levelValue;
        _logger.Information("[WEB] Log display level changed to {Level}", InMemoryLogSink.Instance.DisplayLevel);
        response.StatusCode = 200;
    }

    private void HandleSetLogLimitRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var limit))
        {
            response.StatusCode = 400;
            return;
        }

        // Validate limit is one of the allowed values
        if (limit != 50 && limit != 100 && limit != 200 && limit != 500 && limit != 1000)
        {
            response.StatusCode = 400;
            return;
        }

        InMemoryLogSink.Instance.DisplayLimit = limit;
        _logger.Information("[WEB] Log display limit changed to {Limit}", limit);
        response.StatusCode = 200;
    }

    private void HandleSetSessionLimitRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3 || !int.TryParse(parts[2], out var limit))
        {
            response.StatusCode = 400;
            return;
        }

        var tunnel = parts[1].ToLowerInvariant();

        // Validate limit is one of the allowed values
        if (limit != 50 && limit != 100 && limit != 200 && limit != 500)
        {
            response.StatusCode = 400;
            return;
        }

        switch (tunnel)
        {
            case "v2":
                SessionLog.V2.DisplayLimit = limit;
                break;
            case "v3":
                SessionLog.V3.DisplayLimit = limit;
                break;
            default:
                response.StatusCode = 400;
                return;
        }

        _logger.Information("[WEB] {Tunnel} session display limit changed to {Limit}", tunnel.ToUpper(), limit);
        response.StatusCode = 200;
    }

    private void HandleSetNameRequest(string path, HttpListenerResponse response)
    {
        // Only allow if --rowtagmode is enabled
        if (!_options.Diagnostics.RowtagMode)
        {
            response.StatusCode = 403; // Forbidden - rowtagmode not enabled
            return;
        }

        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            response.StatusCode = 400;
            return;
        }

        var newName = HttpUtility.UrlDecode(parts[1]);

        // Validate name: not empty, max 50 chars, no semicolons
        if (string.IsNullOrWhiteSpace(newName) || newName.Length > 50 || newName.Contains(';'))
        {
            response.StatusCode = 400;
            return;
        }

        var oldName = _options.Server.Name;
        _options.Server.Name = newName;
        _logger.Warning("[WEB] Server name changed from '{OldName}' to '{NewName}'", oldName, newName);
        response.StatusCode = 200;
    }

    private void HandleSetViewRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            response.StatusCode = 400;
            return;
        }

        var view = parts[1].ToLowerInvariant();

        // Validate view is one of the allowed values
        if (view != "logs" && view != "v3sessions" && view != "v2sessions" && view != "trace" && view != "tracev2" && view != "tracev3")
        {
            response.StatusCode = 400;
            return;
        }

        // Block trace views if --trace was not enabled at startup
        if ((view == "trace" || view == "tracev2" || view == "tracev3") && !_options.Diagnostics.TraceAllConnections)
        {
            response.StatusCode = 403;
            return;
        }

        InMemoryLogSink.Instance.DisplayView = view;
        response.StatusCode = 200;
    }

    private void HandleTraceStartRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            response.StatusCode = 400;
            return;
        }

        var ip = HttpUtility.UrlDecode(parts[2]);
        if (ConnectionTracer.Instance.StartTracing(ip))
        {
            _logger.Warning("[WEB] Started tracing IP {IP}", ip);
            response.StatusCode = 200;
        }
        else
        {
            response.StatusCode = 400;
        }
    }

    private void HandleTraceStopRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            response.StatusCode = 400;
            return;
        }

        var ip = HttpUtility.UrlDecode(parts[2]);
        if (ConnectionTracer.Instance.StopTracing(ip))
        {
            _logger.Warning("[WEB] Stopped tracing IP {IP}", ip);
            response.StatusCode = 200;
        }
        else
        {
            response.StatusCode = 404;
        }
    }

    private void HandleTraceStopAllRequest(HttpListenerResponse response)
    {
        ConnectionTracer.Instance.StopAllTracing();
        ConnectionTracer.Instance.TraceAllIps = false;
        _logger.Warning("[WEB] Stopped all IP tracing");
        response.StatusCode = 200;
    }

    private void HandleTraceAllOnRequest(HttpListenerResponse response)
    {
        ConnectionTracer.Instance.TraceAllIps = true;
        ConnectionTracer.Instance.TraceAllLevel = TraceLevel.Verbose;
        _logger.Warning("[WEB] Trace ALL IPs enabled (resource intensive!)");
        response.StatusCode = 200;
    }

    private void HandleTraceAllOffRequest(HttpListenerResponse response)
    {
        ConnectionTracer.Instance.TraceAllIps = false;
        _logger.Warning("[WEB] Trace ALL IPs disabled");
        response.StatusCode = 200;
    }

    private void HandleTraceAllImportantRequest(HttpListenerResponse response)
    {
        ConnectionTracer.Instance.TraceAllIps = true;
        ConnectionTracer.Instance.TraceAllLevel = TraceLevel.Important;
        _logger.Warning("[WEB] Trace ALL IPs enabled (Important events only - resource efficient)");
        response.StatusCode = 200;
    }

    private void HandleSetTraceLevelRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            response.StatusCode = 400;
            return;
        }

        var levelStr = parts[2].ToLowerInvariant();
        TraceLevel level = levelStr switch
        {
            "verbose" => TraceLevel.Verbose,
            "important" => TraceLevel.Important,
            "errors" => TraceLevel.ErrorsOnly,
            _ => TraceLevel.Important
        };

        ConnectionTracer.Instance.DisplayLevel = level;
        _logger.Information("[WEB] Trace level set to {Level}", level);
        response.StatusCode = 200;
    }

    #endregion

    #region Response Builders

    private async Task SendJsonResponseAsync(HttpListenerResponse response)
    {
        var status = BuildStatus();
        var json = JsonSerializer.Serialize(status, AppJsonContext.Default.ServerStatus);
        var buffer = Encoding.UTF8.GetBytes(json);

        response.ContentType = "application/json; charset=utf-8";
        response.ContentLength64 = buffer.Length;
        await response.OutputStream.WriteAsync(buffer);
    }

    private async Task SendHtmlResponseAsync(HttpListenerResponse response, bool isAuthenticated)
    {
        var status = BuildStatus();
        var html = BuildHtmlDashboard(status, isAuthenticated);
        var buffer = Encoding.UTF8.GetBytes(html);

        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength64 = buffer.Length;
        await response.OutputStream.WriteAsync(buffer);
    }

    private ServerStatus BuildStatus()
    {
        var securityStats = _securityManager.GetStatistics();

        return new ServerStatus
        {
            Server = new ServerInfo
            {
                Name = _options.Server.Name,
                Uptime = FormatUptime(DateTime.UtcNow - _startTime),
                MaxClients = _options.Server.MaxClients
            },
            TunnelV3 = _tunnelV3 != null ? new TunnelInfo
            {
                Port = _options.TunnelV3.Port,
                Enabled = _options.TunnelV3.Enabled,
                ConnectedClients = _tunnelV3.EstablishedClients,
                UniqueIps = _tunnelV3.UniqueIpCount,
                Maintenance = _tunnelV3.IsMaintenanceMode
            } : null,
            TunnelV2 = _tunnelV2 != null ? new TunnelInfo
            {
                Port = _options.TunnelV2.Port,
                Enabled = _options.TunnelV2.Enabled,
                ConnectedClients = _tunnelV2.ConnectedClients,
                UniqueIps = _tunnelV2.UniqueIpCount,
                Maintenance = _tunnelV2.IsMaintenanceMode
            } : null,
            Security = new SecurityInfo
            {
                V3PacketValidation = TunnelV3PacketValidation.Enabled,
                V3DDoSProtection = _options.TunnelV3.DDoSProtectionEnabled,
                V2DDoSProtection = _options.TunnelV2.DDoSProtectionEnabled,
                TrackedIps = securityStats.TrackedIps,
                LocalBlacklist = securityStats.LocalBlacklistCount,
                ExternalBlacklist = securityStats.ExternalBlacklistCount,
                ActiveConnections = securityStats.TotalConnections
            }
        };
    }

    private string BuildHtmlDashboard(ServerStatus status, bool isAuthenticated)
    {
        var sb = new StringBuilder();

        sb.AppendLine("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta http-equiv="refresh" content="15">
                <title>CnCNet Tunnel Server</title>
                <style>
                    :root {
                        --bg-primary: #0f172a;
                        --bg-card: #1e293b;
                        --bg-input: #0f172a;
                        --border: #334155;
                        --text: #f1f5f9;
                        --text-muted: #64748b;
                        --accent: #3b82f6;
                        --success: #10b981;
                        --warning: #f59e0b;
                        --danger: #ef4444;
                        --purple: #a855f7;
                        --pink: #ec4899;
                    }
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: 'Segoe UI', Tahoma, sans-serif;
                        background: var(--bg-primary);
                        color: var(--text);
                        min-height: 100vh;
                        padding: 20px;
                    }
                    .container {
                        max-width: 1200px;
                        margin: 0 auto;
                    }
                    .page-header {
                        text-align: center;
                        margin-bottom: 20px;
                    }
                    .page-header h1 {
                        color: var(--accent);
                        font-size: 1.8rem;
                        margin-bottom: 5px;
                    }
                    .page-header .subtitle {
                        color: var(--text-muted);
                        font-size: 0.9rem;
                    }
                    .server-name-input {
                        background: transparent;
                        border: none;
                        border-bottom: 1px dashed var(--text-muted);
                        color: var(--text-muted);
                        font-size: 0.9rem;
                        font-family: inherit;
                        padding: 0 2px;
                        outline: none;
                        width: 280px;
                        text-align: center;
                    }
                    .server-name-input:focus { border-color: var(--accent); color: var(--text); }
                    .server-name-input.saving { border-color: var(--warning); }
                    .server-name-input.success { border-color: var(--success); color: var(--success); }
                    .server-name-input.error { border-color: var(--danger); color: var(--danger); }
                    .stats-bar {
                        background: var(--bg-card);
                        border: 1px solid var(--border);
                        border-radius: 10px;
                        padding: 12px 20px;
                        margin-bottom: 20px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        flex-wrap: wrap;
                        gap: 15px;
                    }
                    .stat-item {
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        min-width: 120px;
                    }
                    .stat-item-label {
                        font-size: 0.65rem;
                        color: var(--text-muted);
                        text-transform: uppercase;
                        margin-bottom: 4px;
                    }
                    .stat-item-value {
                        font-family: 'Consolas', monospace;
                        font-size: 0.9rem;
                        color: var(--text);
                        margin-bottom: 4px;
                    }
                    .stat-item-bar {
                        width: 80px;
                        height: 4px;
                        background: var(--bg-primary);
                        border-radius: 2px;
                        overflow: hidden;
                    }
                    .stat-item-fill {
                        height: 100%;
                        border-radius: 2px;
                    }
                    .stat-item-fill.blue { background: var(--accent); }
                    .stat-item-fill.purple { background: var(--purple); }
                    .stat-item-fill.green { background: var(--success); }
                    .stat-item.funfact {
                        background: linear-gradient(135deg, var(--accent) 0%, var(--purple) 100%);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        background-clip: text;
                    }
                    .stat-item.funfact .stat-item-value {
                        font-size: 1.1rem;
                        font-weight: 600;
                    }
                    .grid {
                        display: grid;
                        grid-template-columns: repeat(4, 1fr);
                        gap: 15px;
                        margin-bottom: 20px;
                    }
                    @media (max-width: 1200px) {
                        .grid { grid-template-columns: repeat(2, 1fr); }
                    }
                    @media (max-width: 768px) {
                        .grid { grid-template-columns: 1fr; }
                    }
                    .bottom-row {
                        display: grid;
                        grid-template-columns: 1fr 2fr;
                        gap: 15px;
                        margin-bottom: 20px;
                    }
                    @media (max-width: 1000px) {
                        .bottom-row { grid-template-columns: 1fr; }
                    }
                    .card {
                        background: var(--bg-card);
                        border: 1px solid var(--border);
                        border-radius: 10px;
                        padding: 15px;
                    }
                    .card h2 {
                        color: var(--accent);
                        font-size: 1rem;
                        margin-bottom: 15px;
                        padding-bottom: 10px;
                        border-bottom: 1px solid var(--border);
                    }
                    .stat {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 8px 0;
                        border-bottom: 1px solid var(--border);
                    }
                    .stat:last-child { border-bottom: none; }
                    .stat-label { color: var(--text-muted); }
                    .stat-value { color: var(--success); font-weight: 600; }
                    .status-ok { color: var(--success); }
                    .status-maint { color: var(--warning); }
                    .status-disabled { color: var(--danger); }
                    .warning { color: var(--warning); }
                    .danger { color: var(--danger); }
                    .toggle-row {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 10px 0;
                        border-bottom: 1px solid var(--border);
                    }
                    .toggle-row:last-child { border-bottom: none; }
                    .toggle-label { color: var(--text-muted); }
                    .toggle-switch {
                        position: relative;
                        width: 50px;
                        height: 26px;
                    }
                    .toggle-switch input { opacity: 0; width: 0; height: 0; }
                    .toggle-slider {
                        position: absolute;
                        cursor: pointer;
                        top: 0; left: 0; right: 0; bottom: 0;
                        background-color: var(--danger);
                        transition: .3s;
                        border-radius: 26px;
                    }
                    .toggle-slider:before {
                        position: absolute;
                        content: "";
                        height: 20px;
                        width: 20px;
                        left: 3px;
                        bottom: 3px;
                        background-color: white;
                        transition: .3s;
                        border-radius: 50%;
                    }
                    input:checked + .toggle-slider { background-color: var(--success); }
                    input:checked + .toggle-slider:before { transform: translateX(24px); }
                    .limit-input {
                        width: 70px;
                        padding: 5px 8px;
                        border: 1px solid var(--border);
                        border-radius: 6px;
                        background: var(--bg-input);
                        color: var(--success);
                        font-size: 14px;
                        font-weight: 600;
                        text-align: center;
                        -moz-appearance: textfield;
                    }
                    .limit-input::-webkit-outer-spin-button,
                    .limit-input::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
                    .limit-input:focus { outline: none; border-color: var(--accent); }
                    .log-card {
                        background: var(--bg-card);
                        border: 1px solid var(--border);
                        border-radius: 10px;
                        padding: 15px;
                    }
                    .log-container {
                        max-height: 400px;
                        overflow-y: auto;
                        font-family: 'Consolas', monospace;
                        font-size: 12px;
                        background: var(--bg-primary);
                        border-radius: 6px;
                        padding: 10px;
                    }
                    .log-entry { padding: 3px 0; border-bottom: 1px solid var(--border); }
                    .log-time { color: var(--text-muted); }
                    .log-info { color: var(--accent); }
                    .log-warning { color: var(--warning); }
                    .log-error { color: var(--danger); }
                    .log-fatal { color: var(--danger); font-weight: bold; }
                    .log-debug { color: var(--text-muted); }
                    .log-verbose { color: var(--text-muted); }
                    .blocked-list { max-height: 200px; overflow-y: auto; }
                    .blocked-ip {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 8px 0;
                        border-bottom: 1px solid var(--border);
                    }
                    .blocked-ip:last-child { border-bottom: none; }
                    .unblock-btn {
                        background: var(--danger);
                        color: #fff;
                        border: none;
                        padding: 4px 10px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 12px;
                    }
                    .unblock-btn:hover { opacity: 0.8; }
                    .log-select {
                        padding: 6px 10px;
                        border: 1px solid var(--border);
                        border-radius: 6px;
                        background: var(--bg-input);
                        color: var(--accent);
                        font-size: 13px;
                        cursor: pointer;
                    }
                    .log-select:focus { outline: none; border-color: var(--accent); }
                    .log-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 15px;
                        padding-bottom: 10px;
                        border-bottom: 1px solid var(--border);
                    }
                    .log-header h2 { color: var(--accent); margin-bottom: 0; padding-bottom: 0; border-bottom: none; }
                    .log-controls { display: flex; gap: 10px; align-items: center; }
                    .log-controls label { color: var(--text-muted); font-size: 12px; }
                    .session-entry {
                        display: flex;
                        justify-content: space-between;
                        padding: 4px 8px;
                        border-bottom: 1px solid var(--border);
                        font-size: 12px;
                    }
                    .session-entry:hover { background: var(--bg-primary); }
                    .session-ip { color: var(--accent); font-family: monospace; }
                    .session-duration { color: var(--success); }
                    .session-time { color: var(--text-muted); }
                    .trace-info { color: var(--accent); }
                    .trace-success { color: var(--success); }
                    .trace-blocked { color: var(--danger); }
                    .trace-warning { color: var(--warning); }
                    .trace-error { color: var(--danger); }
                    .trace-default { color: var(--text-muted); }
                    .trace-entry {
                        display: flex;
                        gap: 10px;
                        padding: 4px 8px;
                        border-bottom: 1px solid var(--border);
                        font-size: 12px;
                    }
                    .trace-entry:hover { background: var(--bg-primary); }
                    .trace-type { min-width: 160px; font-weight: 500; }
                    .trace-details { color: var(--text-muted); flex: 1; }
                    .trace-controls { display: flex; gap: 10px; margin-bottom: 15px; align-items: center; flex-wrap: wrap; }
                    .trace-input {
                        padding: 8px 12px;
                        border: 1px solid var(--border);
                        border-radius: 6px;
                        background: var(--bg-input);
                        color: var(--text);
                        font-size: 14px;
                        width: 180px;
                    }
                    .trace-input:focus { outline: none; border-color: var(--accent); }
                    .trace-btn {
                        padding: 8px 16px;
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 13px;
                        font-weight: 500;
                    }
                    .trace-btn.start { background: var(--accent); color: var(--bg-primary); }
                    .trace-btn.stop { background: var(--danger); color: #fff; }
                    .trace-btn:hover { opacity: 0.9; }
                    .traced-ips { display: flex; gap: 8px; flex-wrap: wrap; margin-left: 10px; }
                    .traced-ip-tag {
                        background: var(--border);
                        color: var(--accent);
                        padding: 4px 10px;
                        border-radius: 4px;
                        font-size: 12px;
                        display: flex;
                        align-items: center;
                        gap: 6px;
                    }
                    .traced-ip-tag .remove { cursor: pointer; color: var(--danger); font-weight: bold; }
                    .maint-btn {
                        padding: 6px 12px;
                        border: 1px solid var(--border);
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 12px;
                        transition: all 0.3s;
                    }
                    .maint-btn.active { background: var(--warning); color: var(--bg-primary); border-color: var(--warning); }
                    .maint-btn.inactive { background: var(--bg-input); color: var(--text-muted); }
                    .maint-btn:hover { border-color: var(--accent); }
                    .logout-btn {
                        position: fixed;
                        top: 15px;
                        right: 15px;
                        background: var(--bg-card);
                        color: var(--text-muted);
                        border: 1px solid var(--border);
                        padding: 8px 15px;
                        border-radius: 6px;
                        cursor: pointer;
                        text-decoration: none;
                        font-size: 12px;
                    }
                    .logout-btn:hover { background: var(--danger); color: white; border-color: var(--danger); }
                    .footer {
                        text-align: center;
                        margin-top: 30px;
                        color: var(--text-muted);
                        font-size: 0.8rem;
                    }
                    .footer .heart { color: var(--danger); }
                </style>
            </head>
            <body>
            """);

        // Logout button (outside container, fixed position)
        if (isAuthenticated)
        {
            sb.AppendLine("        <a href=\"/logout\" class=\"logout-btn\">Logout</a>");
        }

        // Start container
        sb.AppendLine("        <div class=\"container\">");

        // Page header - centered title and subtitle like old design
        // Server name is editable if --rowtagmode is enabled
        var serverNameHtml = _options.Diagnostics.RowtagMode
            ? $"""<input type="text" class="server-name-input" id="serverNameInput" value="{HttpUtility.HtmlEncode(status.Server.Name)}" onkeydown="if(event.key==='Enter')setServerName(this.value)">"""
            : HttpUtility.HtmlEncode(status.Server.Name);

        // System stats for stats bar
        var cpuPercent = _cpuUsagePercent;
        var cpuDisplay = cpuPercent.ToString("F1");
        var ramUsed = _memoryUsageMB;
        var ramTotal = _totalMemoryMB;
        var ramPercent = ramTotal > 0 ? (ramUsed * 100.0 / ramTotal) : 0;
        var logSizeMB = _logFileSizeKB / 1024.0;
        var logSizeDisplay = logSizeMB >= 1 ? $"{logSizeMB:F0} MB" : $"{_logFileSizeKB} KB";
        var freeDiskGB = _freeDiskSpaceGB;
        var freeDiskMB = freeDiskGB * 1024.0;
        var diskUsedPercent = freeDiskMB > 0 ? Math.Min(100, (logSizeMB / freeDiskMB) * 100) : 0;
        var avgSessionDisplay = _avgSessionMinutes > 0 ? $"{_avgSessionMinutes:F1} min" : "...";

        sb.AppendLine($"""
                <div class="page-header">
                    <h1>CnCNet Tunnel Server</h1>
                    <div class="subtitle">{serverNameHtml} | Uptime: {status.Server.Uptime}</div>
                </div>
                <div class="stats-bar">
                    <div class="stat-item">
                        <span class="stat-item-label">CPU</span>
                        <span class="stat-item-value">{cpuDisplay}%</span>
                        <div class="stat-item-bar"><div class="stat-item-fill blue" style="width:{cpuPercent:F0}%"></div></div>
                    </div>
                    <div class="stat-item">
                        <span class="stat-item-label">Memory</span>
                        <span class="stat-item-value">{ramUsed} / {ramTotal} MB</span>
                        <div class="stat-item-bar"><div class="stat-item-fill purple" style="width:{ramPercent:F0}%"></div></div>
                    </div>
                    <div class="stat-item">
                        <span class="stat-item-label">Logs / Disk</span>
                        <span class="stat-item-value">{logSizeDisplay} / {freeDiskGB} GB</span>
                        <div class="stat-item-bar"><div class="stat-item-fill green" style="width:{diskUsedPercent:F1}%"></div></div>
                    </div>
                    <div class="stat-item funfact">
                        <span class="stat-item-label">&#127775; Avg Session</span>
                        <span class="stat-item-value">{avgSessionDisplay}</span>
                    </div>
                </div>
                <div class="grid">
            """);

        // Tunnel V3 Card with maintenance toggle
        if (status.TunnelV3 != null)
        {
            var (v3Status, v3Icon, v3Class) = status.TunnelV3.Maintenance
                ? ("Maintenance", "&#128295;", "status-maint")
                : status.TunnelV3.Enabled
                    ? ("Online", "&#9989;", "status-ok")
                    : ("Offline", "&#10060;", "status-disabled");

            var v3MaintClass = status.TunnelV3.Maintenance ? "active" : "inactive";

            sb.AppendLine($"""
                    <div class="card">
                        <h2>&#128225; Tunnel V3 (Port {status.TunnelV3.Port})</h2>
                        <div class="stat">
                            <span class="stat-label">Status</span>
                            <span class="stat-value {v3Class}">{v3Icon} {v3Status}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Connected Clients</span>
                            <span class="stat-value">{status.TunnelV3.ConnectedClients} / {status.Server.MaxClients}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Unique IPs</span>
                            <span class="stat-value">{status.TunnelV3.UniqueIps}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Maintenance Mode</span>
                            <button class="maint-btn {v3MaintClass}" onclick="toggleMaint('v3')">{(status.TunnelV3.Maintenance ? "ON" : "OFF")}</button>
                        </div>
                    </div>
                """);
        }

        // Tunnel V2 Card with maintenance toggle
        if (status.TunnelV2 != null)
        {
            var (v2Status, v2Icon, v2Class) = status.TunnelV2.Maintenance
                ? ("Maintenance", "&#128295;", "status-maint")
                : status.TunnelV2.Enabled
                    ? ("Online", "&#9989;", "status-ok")
                    : ("Offline", "&#10060;", "status-disabled");

            var v2MaintClass = status.TunnelV2.Maintenance ? "active" : "inactive";

            sb.AppendLine($"""
                    <div class="card">
                        <h2>&#128225; Tunnel V2 (Port {status.TunnelV2.Port})</h2>
                        <div class="stat">
                            <span class="stat-label">Status</span>
                            <span class="stat-value {v2Class}">{v2Icon} {v2Status}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Connected Clients</span>
                            <span class="stat-value">{status.TunnelV2.ConnectedClients} / {status.Server.MaxClients}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Unique IPs</span>
                            <span class="stat-value">{status.TunnelV2.UniqueIps}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Maintenance Mode</span>
                            <button class="maint-btn {v2MaintClass}" onclick="toggleMaint('v2')">{(status.TunnelV2.Maintenance ? "ON" : "OFF")}</button>
                        </div>
                    </div>
                """);
        }

        // Security Card with toggle switches
        var v3ValidationChecked = status.Security.V3PacketValidation ? "checked" : "";
        var v3DDoSChecked = status.Security.V3DDoSProtection ? "checked" : "";
        var v2DDoSChecked = status.Security.V2DDoSProtection ? "checked" : "";
        var localBlacklistClass = status.Security.LocalBlacklist > 0 ? "warning" : "";

        sb.AppendLine($"""
                <div class="card">
                    <h2>&#128737; Security</h2>
                    <div class="toggle-row">
                        <span class="toggle-label">V3 Packet Validation</span>
                        <label class="toggle-switch">
                            <input type="checkbox" {v3ValidationChecked} onchange="toggle('v3validation')">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                    <div class="toggle-row">
                        <span class="toggle-label">V3 DDoS Protection</span>
                        <label class="toggle-switch">
                            <input type="checkbox" {v3DDoSChecked} onchange="toggle('v3ddos')">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                    <div class="toggle-row">
                        <span class="toggle-label">V2 DDoS Protection</span>
                        <label class="toggle-switch">
                            <input type="checkbox" {v2DDoSChecked} onchange="toggle('v2ddos')">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Tracked IPs</span>
                        <span class="stat-value">{status.Security.TrackedIps}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Local Blacklist</span>
                        <span class="stat-value {localBlacklistClass}">{status.Security.LocalBlacklist}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">External Blacklist</span>
                        <span class="stat-value">{status.Security.ExternalBlacklist}</span>
                    </div>
                </div>
            """);

        // Configuration Card with editable IP limits (Enter to save)
        sb.AppendLine($"""
                <div class="card">
                    <h2>&#9881; Configuration</h2>
                    <div class="stat">
                        <span class="stat-label">Max Clients</span>
                        <span class="stat-value">{_options.Server.MaxClients}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">IP Limit V3 (max 40)</span>
                        <input type="number" class="limit-input" value="{_options.TunnelV3.IpLimit}" min="1" max="40" onkeydown="if(event.key==='Enter')setLimit('v3',this.value)">
                    </div>
                    <div class="stat">
                        <span class="stat-label">IP Limit V2 (max 40)</span>
                        <input type="number" class="limit-input" value="{_options.TunnelV2.IpLimit}" min="1" max="40" onkeydown="if(event.key==='Enter')setLimit('v2',this.value)">
                    </div>
                    <div class="stat">
                        <span class="stat-label">Blacklist Duration (hours)</span>
                        <input type="number" class="limit-input" value="{_options.Security.IpBlacklistDurationHours}" min="1" max="168" onkeydown="if(event.key==='Enter')setBlacklistDuration(this.value)">
                    </div>
                    <div class="stat">
                        <span class="stat-label">Client Timeout</span>
                        <span class="stat-value">{_options.Server.ClientTimeout}s</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">P2P/STUN</span>
                        <span class="stat-value {(_options.PeerToPeer.Enabled ? "status-ok" : "status-disabled")}">{(_options.PeerToPeer.Enabled ? "Enabled" : "Disabled")}</span>
                    </div>
                </div>
            """);

        sb.AppendLine("</div>");  // Close grid

        // Bottom row: Blocked IPs (left, narrower) + Logs (right, wider)
        sb.AppendLine("<div class=\"bottom-row\">");

        // Blocked IPs Card
        var blockedIps = _securityManager.GetBlockedIps().ToList();
        sb.AppendLine("""
                <div class="card">
                    <h2>&#128683; Blocked IPs (Local)</h2>
            """);

        if (blockedIps.Count == 0)
        {
            sb.AppendLine("        <div class=\"stat\"><span class=\"stat-label\">No IPs currently blocked</span></div>");
        }
        else
        {
            sb.AppendLine("        <div class=\"blocked-list\">");
            foreach (var ip in blockedIps)
            {
                var encodedIp = HttpUtility.UrlEncode(ip.IpAddress);
                sb.AppendLine($"""
                            <div class="blocked-ip">
                                <span><span class="danger">{ip.IpAddress}</span> <span class="stat-label">({ip.RemainingMinutes} min)</span></span>
                                <button class="unblock-btn" onclick="unblock('{encodedIp}')">Unblock</button>
                            </div>
                    """);
            }
            sb.AppendLine("        </div>");
        }
        sb.AppendLine("    </div>");

        // Unified Log/Sessions Card with View dropdown
        var currentView = InMemoryLogSink.Instance.DisplayView;

        // If trace view is selected but --trace was not enabled, reset to logs
        if ((currentView == "trace" || currentView == "tracev2" || currentView == "tracev3") && !_options.Diagnostics.TraceAllConnections)
        {
            currentView = "logs";
            InMemoryLogSink.Instance.DisplayView = "logs";
        }

        var currentLogLevel = (int)InMemoryLogSink.Instance.DisplayLevel;
        var currentLogLimit = InMemoryLogSink.Instance.DisplayLimit;
        var v3SessionCount = SessionLog.V3.TotalCount;
        var v2SessionCount = SessionLog.V2.TotalCount;
        var tracedIps = _options.Diagnostics.TraceAllConnections ? ConnectionTracer.Instance.TracedIps.ToList() : [];
        var traceAllEventCount = _options.Diagnostics.TraceAllConnections
            ? ConnectionTracer.Instance.GetEventCount()
            : 0;
        var traceV2EventCount = _options.Diagnostics.TraceAllConnections
            ? ConnectionTracer.Instance.GetEventCount(TunnelSource.V2)
            : 0;
        var traceV3EventCount = _options.Diagnostics.TraceAllConnections
            ? ConnectionTracer.Instance.GetEventCount(TunnelSource.V3)
            : 0;

        // Determine title based on current view
        var (viewTitle, viewIcon) = currentView switch
        {
            "v3sessions" => ($"V3 Sessions ({v3SessionCount})", "&#128101;"),
            "v2sessions" => ($"V2 Sessions ({v2SessionCount})", "&#128101;"),
            "tracev3" => ($"IP Trace V3 ({traceV3EventCount})", "&#128269;"),
            "tracev2" => ($"IP Trace V2 ({traceV2EventCount})", "&#128269;"),
            "trace" => ($"IP Trace All ({traceAllEventCount})", "&#128269;"),
            _ => ("Log Messages", "&#128196;")
        };

        sb.AppendLine($"""
                <div class="log-card">
                    <div class="log-header">
                        <h2>{viewIcon} {viewTitle}</h2>
                        <div class="log-controls">
                            <select class="log-select" onchange="setView(this.value)">
                                <option value="logs" {(currentView == "logs" ? "selected" : "")}>Logs</option>
                                <option value="v3sessions" {(currentView == "v3sessions" ? "selected" : "")}>V3 Sessions ({v3SessionCount})</option>
                                <option value="v2sessions" {(currentView == "v2sessions" ? "selected" : "")}>V2 Sessions ({v2SessionCount})</option>
            """);

        // Only show IP Trace options if trace mode was enabled via --trace
        if (_options.Diagnostics.TraceAllConnections)
        {
            sb.AppendLine($"                                <option value=\"tracev3\" {(currentView == "tracev3" ? "selected" : "")}>IP Trace V3 ({traceV3EventCount})</option>");
            sb.AppendLine($"                                <option value=\"tracev2\" {(currentView == "tracev2" ? "selected" : "")}>IP Trace V2 ({traceV2EventCount})</option>");
            sb.AppendLine($"                                <option value=\"trace\" {(currentView == "trace" ? "selected" : "")}>IP Trace All ({traceAllEventCount})</option>");
        }

        sb.AppendLine("                            </select>");

        // Show Level dropdown for logs view
        if (currentView == "logs")
        {
            sb.AppendLine("""
                            <select class="log-select" onchange="setLogLevel(this.value)">
                """);

            foreach (var (name, value) in InMemoryLogSink.GetAvailableLevels())
            {
                var selected = value == currentLogLevel ? "selected" : "";
                sb.AppendLine($"                                <option value=\"{value}\" {selected}>{name}</option>");
            }

            sb.AppendLine("                            </select>");
        }

        // Show Level dropdown for trace views (only if --rowtagmode enabled)
        if (_options.Diagnostics.TraceAllConnections && (currentView == "trace" || currentView == "tracev2" || currentView == "tracev3"))
        {
            var currentTraceLevel = ConnectionTracer.Instance.DisplayLevel;
            sb.AppendLine("""
                            <select class="log-select" onchange="setTraceLevel(this.value)">
                """);
            sb.AppendLine($"                                <option value=\"verbose\"{(currentTraceLevel == TraceLevel.Verbose ? " selected" : "")}>All Events</option>");
            sb.AppendLine($"                                <option value=\"important\"{(currentTraceLevel == TraceLevel.Important ? " selected" : "")}>Important Only</option>");
            sb.AppendLine($"                                <option value=\"errors\"{(currentTraceLevel == TraceLevel.ErrorsOnly ? " selected" : "")}>Errors Only</option>");
            sb.AppendLine("                            </select>");
        }

        // Show limit dropdown for all views
        sb.AppendLine("""
                            <select class="log-select" onchange="setDisplayLimit(this.value)">
            """);

        foreach (var limit in InMemoryLogSink.GetAvailableLimits())
        {
            int currentLimit = currentView switch
            {
                "logs" or "trace" or "tracev2" or "tracev3" => currentLogLimit,
                "v3sessions" => SessionLog.V3.DisplayLimit,
                "v2sessions" => SessionLog.V2.DisplayLimit,
                _ => currentLogLimit
            };
            var selected = limit == currentLimit ? "selected" : "";
            sb.AppendLine($"                                <option value=\"{limit}\" {selected}>{limit}</option>");
        }

        sb.AppendLine("""
                            </select>
                        </div>
                    </div>
                    <div class="log-container">
            """);

        // Render content based on current view
        if (currentView == "logs")
        {
            var logEntries = InMemoryLogSink.Instance.GetEntries().ToList();
            if (logEntries.Count == 0)
            {
                sb.AppendLine("            <div class=\"log-entry\">No log entries yet</div>");
            }
            else
            {
                foreach (var entry in logEntries)
                {
                    var escapedMessage = HttpUtility.HtmlEncode(entry.Message);
                    sb.AppendLine($"""
                            <div class="log-entry">
                                <span class="log-time">[{entry.Timestamp:HH:mm:ss}]</span>
                                <span class="{entry.LevelClass}">[{entry.Level}]</span>
                                {escapedMessage}
                            </div>
                        """);
                }
            }
        }
        else if (_options.Diagnostics.TraceAllConnections && (currentView == "trace" || currentView == "tracev2" || currentView == "tracev3"))
        {
            // Determine source filter for this trace view (only if --rowtagmode enabled)
            TunnelSource? sourceFilter = currentView switch
            {
                "tracev2" => TunnelSource.V2,
                "tracev3" => TunnelSource.V3,
                _ => null // "trace" shows all
            };

            // Render trace controls
            var traceAllEnabled = ConnectionTracer.Instance.TraceAllIps;
            var traceAllLevel = ConnectionTracer.Instance.TraceAllLevel;
            sb.AppendLine("            <div class=\"trace-controls\">");
            sb.AppendLine("                <input type=\"text\" class=\"trace-input\" id=\"traceIpInput\" placeholder=\"Enter IP to trace...\">");
            sb.AppendLine("                <button class=\"trace-btn start\" onclick=\"startTrace()\">Start Trace</button>");

            // Trace All toggle buttons: OFF -> Important -> ON (Verbose) -> OFF
            if (!traceAllEnabled)
            {
                // OFF state - click goes to Important mode
                sb.AppendLine("                <button class=\"trace-btn\" onclick=\"toggleTraceAllImportant()\" style=\"background:#666;color:#fff;\">Trace ALL: OFF</button>");
            }
            else if (traceAllLevel == TraceLevel.Important)
            {
                // Important mode (resource efficient) - click goes to ON (Verbose)
                sb.AppendLine("                <button class=\"trace-btn\" onclick=\"toggleTraceAll(true)\" style=\"background:#00aa00;color:#fff;\">Trace ALL: Important</button>");
            }
            else
            {
                // ON (Verbose mode, resource intensive) - click goes to OFF
                sb.AppendLine("                <button class=\"trace-btn\" onclick=\"toggleTraceAll(false)\" style=\"background:#ff8800;color:#fff;\">Trace ALL: ON</button>");
            }

            if (tracedIps.Count > 0 || traceAllEnabled)
            {
                sb.AppendLine("                <button class=\"trace-btn stop\" onclick=\"stopAllTraces()\">Stop All</button>");
            }

            if (tracedIps.Count > 0)
            {
                sb.AppendLine("                <div class=\"traced-ips\">");
                foreach (var ip in tracedIps)
                {
                    var encodedIp = HttpUtility.UrlEncode(ip);
                    sb.AppendLine($"                    <span class=\"traced-ip-tag\">{HttpUtility.HtmlEncode(ip)} <span class=\"remove\" onclick=\"stopTrace('{encodedIp}')\">&times;</span></span>");
                }
                sb.AppendLine("                </div>");
            }
            sb.AppendLine("            </div>");

            // Render trace events with source filter
            var traceEvents = ConnectionTracer.Instance.GetEvents(limit: currentLogLimit, sourceFilter: sourceFilter).ToList();
            if (traceEvents.Count == 0)
            {
                if (tracedIps.Count == 0 && !traceAllEnabled)
                {
                    sb.AppendLine("            <div class=\"log-entry\">Enter an IP address above or enable 'Trace ALL' to start tracing connection events</div>");
                }
                else
                {
                    var filterName = sourceFilter switch
                    {
                        TunnelSource.V2 => "V2 tunnel",
                        TunnelSource.V3 => "V3 tunnel",
                        _ => "traced IPs"
                    };
                    sb.AppendLine($"            <div class=\"log-entry\">Waiting for events from {filterName}...</div>");
                }
            }
            else
            {
                foreach (var evt in traceEvents)
                {
                    var escapedDetails = HttpUtility.HtmlEncode(evt.Details);
                    var portInfo = evt.Port.HasValue ? $":{evt.Port}" : "";
                    var sourceTag = currentView == "trace" ? $"<span class=\"{(evt.Source == TunnelSource.V3 ? "status-ok" : evt.Source == TunnelSource.V2 ? "trace-info" : "trace-default")}\">[{evt.Source}]</span> " : "";
                    sb.AppendLine($"""
                            <div class="trace-entry">
                                <span class="log-time">[{evt.Timestamp:HH:mm:ss.fff}]</span>
                                {sourceTag}<span class="session-ip">{evt.IpAddress}{portInfo}</span>
                                <span class="trace-type {evt.CssClass}">{evt.EventTypeName}</span>
                                <span class="trace-details">{escapedDetails}</span>
                            </div>
                        """);
                }
            }
        }
        else
        {
            // Render session entries
            var sessionLog = currentView == "v3sessions" ? SessionLog.V3 : SessionLog.V2;
            var entries = sessionLog.GetEntries().ToList();

            if (entries.Count == 0)
            {
                var tunnelName = currentView == "v3sessions" ? "V3" : "V2";
                sb.AppendLine($"            <div class=\"log-entry\">No {tunnelName} sessions yet</div>");
            }
            else
            {
                foreach (var entry in entries)
                {
                    sb.AppendLine($"""
                            <div class="session-entry">
                                <span><span class="session-ip">{entry.IpAddress}</span></span>
                                <span><span class="session-duration">{entry.DurationFormatted}</span> <span class="session-time">{entry.StartTime.ToLocalTime():HH:mm:ss}</span></span>
                            </div>
                        """);
                }
            }
        }

        sb.AppendLine("        </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("</div>");  // Close bottom-row

        // Footer with signature
        sb.AppendLine("        <div class=\"footer\">");
        sb.AppendLine("            CnCNet Tunnel Server v4.1 | Auto-refresh every 15 seconds | made with <span class=\"heart\">&hearts;</span> by Rowtag");
        sb.AppendLine("        </div>");
        sb.AppendLine("        </div>");  // Close container
        var currentViewForJs = InMemoryLogSink.Instance.DisplayView;
        sb.AppendLine("        <script>");
        sb.AppendLine("            function toggle(option) { fetch('/toggle/' + option).then(r => { if (!r.ok) alert('Toggle failed'); }); }");
        sb.AppendLine("            async function setServerName(name) {");
        sb.AppendLine("                if (!name.trim()) { alert('Name cannot be empty'); return; }");
        sb.AppendLine("                var input = document.getElementById('serverNameInput');");
        sb.AppendLine("                input.className = 'server-name-input saving';");
        sb.AppendLine("                try {");
        sb.AppendLine("                    var r = await fetch('/setname/' + encodeURIComponent(name));");
        sb.AppendLine("                    if (r.ok) {");
        sb.AppendLine("                        input.className = 'server-name-input success';");
        sb.AppendLine("                        input.blur();");
        sb.AppendLine("                    } else {");
        sb.AppendLine("                        input.className = 'server-name-input error';");
        sb.AppendLine("                        alert('Failed to set server name. Max 50 chars, no semicolons.');");
        sb.AppendLine("                    }");
        sb.AppendLine("                } catch(e) {");
        sb.AppendLine("                    input.className = 'server-name-input error';");
        sb.AppendLine("                    alert('Error: ' + e);");
        sb.AppendLine("                }");
        sb.AppendLine("            }");
        sb.AppendLine("            function toggleMaint(tunnel) { fetch('/maintenance/' + tunnel).then(r => { if (r.ok) location.reload(); else alert('Maintenance toggle failed'); }); }");
        sb.AppendLine("            function setLimit(tunnel, value) { fetch('/setlimit/' + tunnel + '/' + value).then(r => { if (!r.ok) alert('Set limit failed'); }); }");
        sb.AppendLine("            function setBlacklistDuration(hours) { fetch('/setblacklistduration/' + hours).then(r => { if (!r.ok) alert('Set duration failed'); }); }");
        sb.AppendLine("            function unblock(ip) { fetch('/unblock/' + ip).then(r => { if (!r.ok) alert('Unblock failed'); }); }");
        sb.AppendLine("            function setLogLevel(level) { fetch('/setloglevel/' + level).then(r => { if (r.ok) location.reload(); else alert('Set log level failed'); }); }");
        sb.AppendLine("            function setLogLimit(limit) { fetch('/setloglimit/' + limit).then(r => { if (r.ok) location.reload(); else alert('Set log limit failed'); }); }");
        sb.AppendLine("            function setSessionLimit(tunnel, limit) { fetch('/setsessionlimit/' + tunnel + '/' + limit).then(r => { if (r.ok) location.reload(); else alert('Set session limit failed'); }); }");
        sb.AppendLine("            function setView(view) { fetch('/setview/' + view).then(r => { if (r.ok) location.reload(); else alert('Set view failed'); }); }");
        sb.AppendLine($"            var currentView = '{currentViewForJs}';");
        sb.AppendLine("            function setDisplayLimit(limit) {");
        sb.AppendLine("                if (currentView === 'logs') { setLogLimit(limit); }");
        sb.AppendLine("                else if (currentView === 'v3sessions') { setSessionLimit('v3', limit); }");
        sb.AppendLine("                else if (currentView === 'v2sessions') { setSessionLimit('v2', limit); }");
        sb.AppendLine("                else if (currentView === 'trace' || currentView === 'tracev2' || currentView === 'tracev3') { setLogLimit(limit); }");
        sb.AppendLine("            }");
        sb.AppendLine("            function startTrace() {");
        sb.AppendLine("                var ip = document.getElementById('traceIpInput').value.trim();");
        sb.AppendLine("                if (!ip) { alert('Please enter an IP address'); return; }");
        sb.AppendLine("                fetch('/trace/start/' + encodeURIComponent(ip)).then(r => { if (r.ok) location.reload(); else alert('Failed to start trace. Invalid IP or limit reached.'); });");
        sb.AppendLine("            }");
        sb.AppendLine("            function stopTrace(ip) { fetch('/trace/stop/' + ip).then(r => { if (r.ok) location.reload(); else alert('Failed to stop trace'); }); }");
        sb.AppendLine("            function stopAllTraces() { fetch('/trace/stopall').then(r => { if (r.ok) location.reload(); else alert('Failed to stop traces'); }); }");
        sb.AppendLine("            function toggleTraceAll(enable) { fetch('/trace/all/' + (enable ? 'on' : 'off')).then(r => { if (r.ok) location.reload(); else alert('Failed to toggle trace all'); }); }");
        sb.AppendLine("            function toggleTraceAllImportant() { fetch('/trace/all/important').then(r => { if (r.ok) location.reload(); else alert('Failed to enable trace important mode'); }); }");
        sb.AppendLine("            function setTraceLevel(level) { fetch('/trace/level/' + level).then(r => { if (r.ok) location.reload(); else alert('Failed to set trace level'); }); }");
        sb.AppendLine("            document.addEventListener('keydown', function(e) { if (e.key === 'Enter' && e.target.id === 'traceIpInput') startTrace(); });");
        sb.AppendLine("        </script>");
        sb.AppendLine("    </body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    private static string FormatUptime(TimeSpan uptime)
    {
        if (uptime.TotalDays >= 1)
            return $"{(int)uptime.TotalDays}d {uptime.Hours}h {uptime.Minutes}m";
        if (uptime.TotalHours >= 1)
            return $"{uptime.Hours}h {uptime.Minutes}m {uptime.Seconds}s";
        return $"{uptime.Minutes}m {uptime.Seconds}s";
    }

    #endregion

    public void Dispose()
    {
        _cts.Cancel();
        _cleanupTimer.Dispose();
        _systemMonitorTimer.Dispose();
        _sessionAvgTimer.Dispose();
        _currentProcess.Dispose();
        _listener.Stop();
        _listener.Close();
        _cts.Dispose();
    }
}

#region Status Models

public sealed class ServerStatus
{
    public required ServerInfo Server { get; init; }
    public TunnelInfo? TunnelV3 { get; init; }
    public TunnelInfo? TunnelV2 { get; init; }
    public required SecurityInfo Security { get; init; }
}

public sealed class ServerInfo
{
    public required string Name { get; init; }
    public required string Uptime { get; init; }
    public int MaxClients { get; init; }
}

public sealed class TunnelInfo
{
    public int Port { get; init; }
    public bool Enabled { get; init; }
    public int ConnectedClients { get; init; }
    public int UniqueIps { get; init; }
    public bool Maintenance { get; init; }
}

public sealed class SecurityInfo
{
    public bool V3PacketValidation { get; init; }
    public bool V3DDoSProtection { get; init; }
    public bool V2DDoSProtection { get; init; }
    public int TrackedIps { get; init; }
    public int LocalBlacklist { get; init; }
    public int ExternalBlacklist { get; init; }
    public long ActiveConnections { get; init; }
}

#endregion

/// <summary>
/// JSON serialization context for AOT/trimmed builds.
/// </summary>
[JsonSerializable(typeof(ServerStatus))]
[JsonSerializable(typeof(List<uint>), TypeInfoPropertyName = "ListUInt32")]
[JsonSerializable(typeof(List<short>), TypeInfoPropertyName = "ListInt16")]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal partial class AppJsonContext : JsonSerializerContext
{
}
