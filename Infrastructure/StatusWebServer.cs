using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;
using CnCNetServer.Configuration;
using CnCNetServer.Logging;
using CnCNetServer.Security;
using CnCNetServer.Tunnels;
using Serilog;

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

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

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

        // Read POST body
        using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        var body = await reader.ReadToEndAsync();
        var formData = HttpUtility.ParseQueryString(body);
        var password = formData["password"];

        if (password == _options.Maintenance.Password)
        {
            // Successful login - create session
            var sessionId = Guid.NewGuid().ToString("N");
            _sessions[sessionId] = DateTime.UtcNow.Add(SessionDuration);

            // Clear failed attempts
            _loginAttempts.TryRemove(clientIp, out _);

            // Set session cookie
            response.SetCookie(new Cookie("session", sessionId) { Path = "/" });

            _logger.Information("[WEB] Successful login from {IP}", clientIp);

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
                _logger.Warning("[WEB] IP {IP} locked out after {Attempts} failed login attempts", clientIp, currentAttempts.Attempts);
                await SendLoginPageAsync(response, $"Too many failed attempts. Locked out for {LockoutDuration.TotalMinutes} minutes.");
            }
            else
            {
                _logger.Warning("[WEB] Failed login attempt from {IP} ({Attempts}/{Max})", clientIp, currentAttempts.Attempts, MaxLoginAttempts);
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

        // Clear cookie
        response.SetCookie(new Cookie("session", "") { Path = "/", Expires = DateTime.Now.AddDays(-1) });
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

    #endregion

    #region Response Builders

    private async Task SendJsonResponseAsync(HttpListenerResponse response)
    {
        var status = BuildStatus();
        var json = JsonSerializer.Serialize(status, JsonOptions);
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
                ConnectedClients = _tunnelV3.ConnectedClients,
                ReservedSlots = 0,
                UniqueIps = _tunnelV3.UniqueIpCount,
                Maintenance = _tunnelV3.IsMaintenanceMode
            } : null,
            TunnelV2 = _tunnelV2 != null ? new TunnelInfo
            {
                Port = _options.TunnelV2.Port,
                Enabled = _options.TunnelV2.Enabled,
                ConnectedClients = _tunnelV2.ConnectedClients,
                ReservedSlots = _tunnelV2.ReservedSlots,
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
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background: #1a1a2e;
                        color: #eee;
                        min-height: 100vh;
                        padding: 20px;
                    }
                    .header {
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .header h1 {
                        color: #00d4ff;
                        font-size: 2rem;
                        margin-bottom: 5px;
                    }
                    .header .info {
                        color: #888;
                        font-size: 0.9rem;
                    }
                    .logout-btn {
                        position: absolute;
                        top: 20px;
                        right: 20px;
                        background: #0f3460;
                        color: #888;
                        border: 1px solid #0f3460;
                        padding: 8px 16px;
                        border-radius: 6px;
                        cursor: pointer;
                        text-decoration: none;
                    }
                    .logout-btn:hover {
                        background: #ff4444;
                        color: #fff;
                        border-color: #ff4444;
                    }
                    .grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                        gap: 20px;
                        max-width: 1400px;
                        margin: 0 auto;
                    }
                    .card {
                        background: #16213e;
                        border-radius: 12px;
                        padding: 20px;
                        border: 1px solid #0f3460;
                    }
                    .card.full-width {
                        grid-column: 1 / -1;
                    }
                    .card.log-card {
                        grid-column: span 3;
                    }
                    @media (max-width: 1000px) {
                        .card.log-card {
                            grid-column: 1 / -1;
                        }
                    }
                    .card h2 {
                        color: #00d4ff;
                        font-size: 1.1rem;
                        margin-bottom: 15px;
                        padding-bottom: 10px;
                        border-bottom: 1px solid #0f3460;
                    }
                    .stat {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 8px 0;
                        border-bottom: 1px solid #0f3460;
                    }
                    .stat:last-child { border-bottom: none; }
                    .stat-label { color: #888; }
                    .stat-value { color: #00ff88; font-weight: 600; }
                    .status-ok { color: #00ff88; }
                    .status-maint { color: #ffaa00; }
                    .status-disabled { color: #ff4444; }
                    .warning { color: #ffaa00; }
                    .danger { color: #ff4444; }
                    .toggle-row {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 10px 0;
                        border-bottom: 1px solid #0f3460;
                    }
                    .toggle-row:last-child { border-bottom: none; }
                    .toggle-label { color: #888; }
                    .toggle-switch {
                        position: relative;
                        width: 50px;
                        height: 26px;
                    }
                    .toggle-switch input {
                        opacity: 0;
                        width: 0;
                        height: 0;
                    }
                    .toggle-slider {
                        position: absolute;
                        cursor: pointer;
                        top: 0; left: 0; right: 0; bottom: 0;
                        background-color: #ff4444;
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
                    input:checked + .toggle-slider {
                        background-color: #00ff88;
                    }
                    input:checked + .toggle-slider:before {
                        transform: translateX(24px);
                    }
                    .limit-input {
                        width: 70px;
                        padding: 5px 8px;
                        border: 1px solid #0f3460;
                        border-radius: 6px;
                        background: #1a1a2e;
                        color: #00ff88;
                        font-size: 14px;
                        font-weight: 600;
                        text-align: center;
                        -moz-appearance: textfield;
                    }
                    .limit-input::-webkit-outer-spin-button,
                    .limit-input::-webkit-inner-spin-button {
                        -webkit-appearance: none;
                        margin: 0;
                    }
                    .limit-input:focus {
                        outline: none;
                        border-color: #00d4ff;
                    }
                    .log-container {
                        max-height: 400px;
                        overflow-y: auto;
                        font-family: 'Consolas', 'Monaco', monospace;
                        font-size: 12px;
                        background: #0d1321;
                        border-radius: 6px;
                        padding: 10px;
                    }
                    .log-entry {
                        padding: 3px 0;
                        border-bottom: 1px solid #1a1a2e;
                    }
                    .log-time { color: #666; }
                    .log-info { color: #00d4ff; }
                    .log-warning { color: #ffaa00; }
                    .log-error { color: #ff4444; }
                    .log-fatal { color: #ff0000; font-weight: bold; }
                    .log-debug { color: #888; }
                    .log-verbose { color: #666; }
                    .blocked-list {
                        max-height: 200px;
                        overflow-y: auto;
                    }
                    .blocked-ip {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 8px 0;
                        border-bottom: 1px solid #0f3460;
                    }
                    .blocked-ip:last-child { border-bottom: none; }
                    .unblock-btn {
                        background: #ff4444;
                        color: #fff;
                        border: none;
                        padding: 4px 10px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 12px;
                    }
                    .unblock-btn:hover {
                        background: #ff6666;
                    }
                    .log-level-select {
                        padding: 6px 10px;
                        border: 1px solid #0f3460;
                        border-radius: 6px;
                        background: #1a1a2e;
                        color: #00d4ff;
                        font-size: 13px;
                        cursor: pointer;
                    }
                    .log-level-select:focus {
                        outline: none;
                        border-color: #00d4ff;
                    }
                    .log-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 15px;
                        padding-bottom: 10px;
                        border-bottom: 1px solid #0f3460;
                    }
                    .log-header h2 {
                        margin-bottom: 0;
                        padding-bottom: 0;
                        border-bottom: none;
                    }
                    .log-controls {
                        display: flex;
                        gap: 10px;
                        align-items: center;
                    }
                    .log-controls label {
                        color: #888;
                        font-size: 12px;
                    }
                    .session-entry {
                        display: flex;
                        justify-content: space-between;
                        padding: 4px 8px;
                        border-bottom: 1px solid #1a1a2e;
                        font-size: 12px;
                    }
                    .session-entry:hover {
                        background: #1a1a2e;
                    }
                    .session-ip { color: #00d4ff; font-family: monospace; }
                    .session-duration { color: #00ff88; }
                    .session-time { color: #666; }
                    .maint-btn {
                        padding: 6px 12px;
                        border: 1px solid #0f3460;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 12px;
                        transition: all 0.3s;
                    }
                    .maint-btn.active {
                        background: #ffaa00;
                        color: #1a1a2e;
                        border-color: #ffaa00;
                    }
                    .maint-btn.inactive {
                        background: #16213e;
                        color: #888;
                    }
                    .maint-btn:hover {
                        border-color: #00d4ff;
                    }
                    .footer {
                        text-align: center;
                        margin-top: 30px;
                        color: #666;
                        font-size: 0.8rem;
                    }
                    .footer .signature {
                        color: #ff6699;
                        margin-top: 5px;
                    }
                </style>
            </head>
            <body>
            """);

        // Logout button
        if (isAuthenticated)
        {
            sb.AppendLine("        <a href=\"/logout\" class=\"logout-btn\">Logout</a>");
        }

        // Header
        sb.AppendLine($"""
                <div class="header">
                    <h1>CnCNet Tunnel Server</h1>
                    <div class="info">{status.Server.Name} | Uptime: {status.Server.Uptime}</div>
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
                            <span class="stat-label">Reserved Slots</span>
                            <span class="stat-value">{status.TunnelV2.ReservedSlots} / {status.Server.MaxClients}</span>
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

        // Blocked IPs Card (side by side with logs)
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

        // Session Log Cards (V3 and V2)
        BuildSessionLogCard(sb, SessionLog.V3, "V3");
        BuildSessionLogCard(sb, SessionLog.V2, "V2");

        // Log Messages Card (spans 3 columns) with level and limit dropdowns
        var logEntries = InMemoryLogSink.Instance.GetEntries().ToList();
        var currentLogLevel = (int)InMemoryLogSink.Instance.DisplayLevel;
        var currentLogLimit = InMemoryLogSink.Instance.DisplayLimit;

        sb.AppendLine("""
                <div class="card log-card">
                    <div class="log-header">
                        <h2>&#128196; Log Messages</h2>
                        <div class="log-controls">
                            <label>Level:</label>
                            <select class="log-level-select" onchange="setLogLevel(this.value)">
            """);

        foreach (var (name, value) in InMemoryLogSink.GetAvailableLevels())
        {
            var selected = value == currentLogLevel ? "selected" : "";
            sb.AppendLine($"                                <option value=\"{value}\" {selected}>{name}</option>");
        }

        sb.AppendLine("""
                            </select>
                            <label>Show:</label>
                            <select class="log-level-select" onchange="setLogLimit(this.value)">
            """);

        foreach (var limit in InMemoryLogSink.GetAvailableLimits())
        {
            var selected = limit == currentLogLimit ? "selected" : "";
            sb.AppendLine($"                                <option value=\"{limit}\" {selected}>{limit}</option>");
        }

        sb.AppendLine("""
                            </select>
                        </div>
                    </div>
                    <div class="log-container">
            """);

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

        sb.AppendLine("        </div>");
        sb.AppendLine("    </div>");

        // Footer with signature and JavaScript
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class=\"footer\">");
        sb.AppendLine("            CnCNet Tunnel Server v4.0 | Auto-refresh every 15 seconds");
        sb.AppendLine("            <div class=\"signature\">made with love by Rowtag</div>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <script>");
        sb.AppendLine("            function toggle(option) { fetch('/toggle/' + option).then(r => { if (!r.ok) alert('Toggle failed'); }); }");
        sb.AppendLine("            function toggleMaint(tunnel) { fetch('/maintenance/' + tunnel).then(r => { if (!r.ok) alert('Maintenance toggle failed'); }); }");
        sb.AppendLine("            function setLimit(tunnel, value) { fetch('/setlimit/' + tunnel + '/' + value).then(r => { if (!r.ok) alert('Set limit failed'); }); }");
        sb.AppendLine("            function setBlacklistDuration(hours) { fetch('/setblacklistduration/' + hours).then(r => { if (!r.ok) alert('Set duration failed'); }); }");
        sb.AppendLine("            function unblock(ip) { fetch('/unblock/' + ip).then(r => { if (!r.ok) alert('Unblock failed'); }); }");
        sb.AppendLine("            function setLogLevel(level) { fetch('/setloglevel/' + level).then(r => { if (r.ok) location.reload(); else alert('Set log level failed'); }); }");
        sb.AppendLine("            function setLogLimit(limit) { fetch('/setloglimit/' + limit).then(r => { if (r.ok) location.reload(); else alert('Set log limit failed'); }); }");
        sb.AppendLine("            function setSessionLimit(tunnel, limit) { fetch('/setsessionlimit/' + tunnel + '/' + limit).then(r => { if (r.ok) location.reload(); else alert('Set session limit failed'); }); }");
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

    private static void BuildSessionLogCard(StringBuilder sb, SessionLog sessionLog, string tunnelName)
    {
        var entries = sessionLog.GetEntries().ToList();
        var currentLimit = sessionLog.DisplayLimit;
        var tunnelLower = tunnelName.ToLowerInvariant();

        sb.AppendLine($"""
                <div class="card">
                    <div class="log-header">
                        <h2>&#128101; {tunnelName} Sessions ({sessionLog.TotalCount})</h2>
                        <div class="log-controls">
                            <label>Show:</label>
                            <select class="log-level-select" onchange="setSessionLimit('{tunnelLower}', this.value)">
            """);

        foreach (var limit in SessionLog.GetAvailableLimits())
        {
            var selected = limit == currentLimit ? "selected" : "";
            sb.AppendLine($"                                <option value=\"{limit}\" {selected}>{limit}</option>");
        }

        sb.AppendLine("""
                            </select>
                        </div>
                    </div>
                    <div class="log-container">
            """);

        if (entries.Count == 0)
        {
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

        sb.AppendLine("        </div>");
        sb.AppendLine("    </div>");
    }

    #endregion

    public void Dispose()
    {
        _cts.Cancel();
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
    public int ReservedSlots { get; init; }
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
