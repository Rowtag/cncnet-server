using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
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
///
/// Security measures implemented:
/// - Brute-force protection (5 attempts, 15 min lockout per IP)
/// - Session cookies with HttpOnly flag
/// - CSRF tokens on all state-changing POST requests
/// - POST body size limit on login (4 KB)
/// - All admin actions via POST (not GET) to prevent CSRF via img/link tags
/// - HtmlEncode on all user-visible output
/// </summary>
public sealed class StatusWebServer : IDisposable
{
    private readonly HttpListener _listener;
    private readonly ILogger _logger;
    private readonly ServiceOptions _options;
    private readonly DateTime _startTime;
    private readonly CancellationTokenSource _cts = new();

    private readonly TunnelV3? _tunnelV3;
    private readonly TunnelV2? _tunnelV2;
    private readonly IpSecurityManager _securityManager;

    // Brute-force protection: IP -> (failedAttempts, lockoutUntil)
    private readonly ConcurrentDictionary<string, (int Attempts, DateTime LockoutUntil)> _loginAttempts = new();
    private const int MaxLoginAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    // Session management with CSRF token per session
    private readonly ConcurrentDictionary<string, SessionData> _sessions = new();
    private static readonly TimeSpan SessionDuration = TimeSpan.FromHours(8);

    // Max POST body size for login (4 KB)
    private const int MaxLoginBodyBytes = 4096;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private sealed record SessionData(DateTime Expiry, string CsrfToken);

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
        _logger.Information("Web monitor running on port {Port}", _options.WebMonitor.Port);

        while (!linkedCts.Token.IsCancellationRequested)
        {
            try
            {
                var context = await _listener.GetContextAsync().WaitAsync(linkedCts.Token);

                // Fire-and-forget with exception logging
                _ = ProcessRequestAsync(context).ContinueWith(
                    t => _logger.Error(t.Exception, "[WEB] Unhandled request error"),
                    TaskContinuationOptions.OnlyOnFaulted);
            }
            catch (OperationCanceledException) { break; }
            catch (HttpListenerException ex) when (ex.ErrorCode == 995) { break; }
            catch (Exception ex) { _logger.Error(ex, "Web monitor error"); }
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
            var requiresAuth = !string.IsNullOrEmpty(_options.Maintenance.Password);

            // Public routes (no auth needed)
            if (path.Equals("/login", StringComparison.OrdinalIgnoreCase))
            {
                if (request.HttpMethod == "POST")
                    await HandleLoginPostAsync(request, response, clientIp);
                else
                    await SendLoginPageAsync(response);
                return;
            }

            if (path.Equals("/logout", StringComparison.OrdinalIgnoreCase))
            {
                HandleLogout(request, response);
                return;
            }

            // Auth check for all other routes
            if (requiresAuth && !IsAuthenticated(request))
            {
                response.Redirect("/login");
                return;
            }

            // Read-only routes (GET)
            if (path.Equals("/json", StringComparison.OrdinalIgnoreCase))
            {
                await SendJsonResponseAsync(response);
                return;
            }

            // ── State-changing routes – POST only + CSRF validation ──────────
            if (request.HttpMethod != "POST")
            {
                // Dashboard root is GET
                if (path == "/" || path.Equals("/index", StringComparison.OrdinalIgnoreCase))
                {
                    await SendHtmlResponseAsync(request, response, requiresAuth);
                    return;
                }
                response.StatusCode = 405; // Method Not Allowed
                return;
            }

            // Validate CSRF token on all POST requests
            if (!ValidateCsrf(request))
            {
                _logger.Warning("[WEB] CSRF validation failed from {IP} on {Path}", clientIp, path);
                response.StatusCode = 403;
                return;
            }

            if (path.StartsWith("/maintenance/", StringComparison.OrdinalIgnoreCase))
                HandleMaintenanceRequest(path, response);
            else if (path.StartsWith("/toggle/", StringComparison.OrdinalIgnoreCase))
                HandleToggleRequest(path, response);
            else if (path.StartsWith("/setlimit/", StringComparison.OrdinalIgnoreCase))
                HandleSetLimitRequest(path, response);
            else if (path.StartsWith("/setblacklistduration/", StringComparison.OrdinalIgnoreCase))
                HandleSetBlacklistDurationRequest(path, response);
            else if (path.StartsWith("/unblock/", StringComparison.OrdinalIgnoreCase))
                HandleUnblockRequest(path, response);
            else
                await SendHtmlResponseAsync(request, response, requiresAuth);
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

    #region Authentication & CSRF

    private bool IsAuthenticated(HttpListenerRequest request)
    {
        var cookie = request.Cookies["session"];
        if (cookie == null || string.IsNullOrEmpty(cookie.Value))
            return false;

        if (_sessions.TryGetValue(cookie.Value, out var session))
        {
            if (DateTime.UtcNow < session.Expiry)
                return true;
            _sessions.TryRemove(cookie.Value, out _);
        }
        return false;
    }

    private bool ValidateCsrf(HttpListenerRequest request)
    {
        // If no password is set, auth is disabled – no CSRF needed
        if (string.IsNullOrEmpty(_options.Maintenance.Password))
            return true;

        var cookie = request.Cookies["session"];
        if (cookie == null || string.IsNullOrEmpty(cookie.Value))
            return false;

        if (!_sessions.TryGetValue(cookie.Value, out var session))
            return false;

        var token = request.Headers["X-CSRF-Token"];
        // Constant-time comparison to prevent timing attacks
        return !string.IsNullOrEmpty(token) &&
               CryptographicOperations.FixedTimeEquals(
                   Encoding.UTF8.GetBytes(token),
                   Encoding.UTF8.GetBytes(session.CsrfToken));
    }

    private string? GetCsrfToken(HttpListenerRequest request)
    {
        var cookie = request.Cookies["session"];
        if (cookie == null || string.IsNullOrEmpty(cookie.Value))
            return null;
        return _sessions.TryGetValue(cookie.Value, out var session) ? session.CsrfToken : null;
    }

    private async Task HandleLoginPostAsync(HttpListenerRequest request, HttpListenerResponse response, string clientIp)
    {
        // Check body size limit (prevent oversized POST)
        if (request.ContentLength64 > MaxLoginBodyBytes)
        {
            response.StatusCode = 413;
            await SendLoginPageAsync(response, "Request too large.");
            return;
        }

        // Check brute-force lockout
        if (_loginAttempts.TryGetValue(clientIp, out var attempt) && DateTime.UtcNow < attempt.LockoutUntil)
        {
            var remaining = (int)(attempt.LockoutUntil - DateTime.UtcNow).TotalMinutes;
            await SendLoginPageAsync(response, $"Too many failed attempts. Try again in {remaining} minutes.");
            return;
        }

        using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        var body = await reader.ReadToEndAsync();
        var formData = HttpUtility.ParseQueryString(body);
        var password = formData["password"];

        if (password == _options.Maintenance.Password)
        {
            // Generate cryptographically secure session ID and CSRF token
            var sessionId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var csrfToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            _sessions[sessionId] = new SessionData(DateTime.UtcNow.Add(SessionDuration), csrfToken);

            _loginAttempts.TryRemove(clientIp, out _);

            // HttpOnly prevents JS access to session cookie
            response.SetCookie(new Cookie("session", sessionId)
            {
                Path = "/",
                HttpOnly = true
            });

            _logger.Information("[WEB] Successful login from {IP}", clientIp);
            response.Redirect("/");
        }
        else
        {
            var currentAttempts = _loginAttempts.AddOrUpdate(
                clientIp,
                _ => (1, DateTime.MinValue),
                (_, existing) => (existing.Attempts + 1, existing.LockoutUntil));

            if (currentAttempts.Attempts >= MaxLoginAttempts)
            {
                _loginAttempts[clientIp] = (currentAttempts.Attempts, DateTime.UtcNow.Add(LockoutDuration));
                _logger.Warning("[WEB] IP {IP} locked out after {Attempts} failed login attempts", clientIp, currentAttempts.Attempts);
                await SendLoginPageAsync(response, $"Too many failed attempts. Locked out for {(int)LockoutDuration.TotalMinutes} minutes.");
            }
            else
            {
                var remaining = MaxLoginAttempts - currentAttempts.Attempts;
                _logger.Warning("[WEB] Failed login from {IP} ({Attempts}/{Max})", clientIp, currentAttempts.Attempts, MaxLoginAttempts);
                await SendLoginPageAsync(response, $"Invalid password. {remaining} attempt(s) remaining.");
            }
        }
    }

    private void HandleLogout(HttpListenerRequest request, HttpListenerResponse response)
    {
        var cookie = request.Cookies["session"];
        if (cookie != null && !string.IsNullOrEmpty(cookie.Value))
            _sessions.TryRemove(cookie.Value, out _);

        response.SetCookie(new Cookie("session", "")
        {
            Path = "/",
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(-1)
        });
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
                    body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee;
                           min-height: 100vh; display: flex; align-items: center; justify-content: center; }
                    .login-box { background: #16213e; border-radius: 12px; padding: 40px;
                                 border: 1px solid #0f3460; width: 100%; max-width: 400px; }
                    h1 { color: #00d4ff; font-size: 1.5rem; margin-bottom: 10px; text-align: center; }
                    .info { color: #888; font-size: 0.85rem; text-align: center; margin-bottom: 25px; }
                    .error { background: #ff444433; border: 1px solid #ff4444; color: #ff6666;
                             padding: 10px; border-radius: 6px; margin-bottom: 20px; font-size: 0.9rem; }
                    label { display: block; color: #888; margin-bottom: 8px; }
                    input[type="password"] { width: 100%; padding: 12px; border: 1px solid #0f3460;
                                            border-radius: 6px; background: #1a1a2e; color: #eee;
                                            font-size: 16px; margin-bottom: 20px; }
                    input[type="password"]:focus { outline: none; border-color: #00d4ff; }
                    button { width: 100%; padding: 12px; background: #00d4ff; color: #1a1a2e;
                             border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; }
                    button:hover { background: #00a8cc; }
                    .hint { color: #666; font-size: 0.75rem; text-align: center; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class="login-box">
                    <h1>CnCNet Tunnel Server</h1>
                    <div class="info">Enter the maintenance password to continue</div>
                    {{errorHtml}}
                    <form method="POST" action="/login">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required autofocus autocomplete="current-password">
                        <button type="submit">Login</button>
                    </form>
                    
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

    #region Request Handlers (all POST + CSRF validated)

    private void HandleMaintenanceRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) { response.StatusCode = 400; return; }

        switch (parts[1].ToLowerInvariant())
        {
            case "v3":
                _tunnelV3?.ToggleMaintenanceMode();
                _logger.Warning("[WEB] V3 Maintenance mode {Status}", _tunnelV3?.IsMaintenanceMode == true ? "ENABLED" : "DISABLED");
                break;
            case "v2":
                _tunnelV2?.ToggleMaintenanceMode();
                _logger.Warning("[WEB] V2 Maintenance mode {Status}", _tunnelV2?.IsMaintenanceMode == true ? "ENABLED" : "DISABLED");
                break;
            default:
                response.StatusCode = 400; return;
        }
        response.StatusCode = 200;
    }

    private void HandleToggleRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) { response.StatusCode = 400; return; }

        switch (parts[1].ToLowerInvariant())
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
                response.StatusCode = 400; return;
        }
        response.StatusCode = 200;
    }

    private void HandleSetLimitRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3 || !int.TryParse(parts[2], out var value) || value < 1 || value > 40)
        {
            response.StatusCode = 400; return;
        }

        switch (parts[1].ToLowerInvariant())
        {
            case "v3": _options.TunnelV3.IpLimit = value; _logger.Warning("[WEB] V3 IP Limit → {Value}", value); break;
            case "v2": _options.TunnelV2.IpLimit = value; _logger.Warning("[WEB] V2 IP Limit → {Value}", value); break;
            default: response.StatusCode = 400; return;
        }
        response.StatusCode = 200;
    }

    private void HandleSetBlacklistDurationRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var hours) || hours < 1 || hours > 168)
        {
            response.StatusCode = 400; return;
        }
        _options.Security.IpBlacklistDurationHours = hours;
        _logger.Warning("[WEB] Blacklist duration → {Hours} hours", hours);
        response.StatusCode = 200;
    }

    private void HandleUnblockRequest(string path, HttpListenerResponse response)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) { response.StatusCode = 400; return; }

        var ip = HttpUtility.UrlDecode(parts[1]);
        response.StatusCode = _securityManager.RemoveFromBlacklist(ip) ? 200 : 404;
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

    private async Task SendHtmlResponseAsync(HttpListenerRequest request, HttpListenerResponse response, bool requiresAuth)
    {
        var csrfToken = requiresAuth ? GetCsrfToken(request) ?? "" : "";
        var status = BuildStatus();
        var html = BuildHtmlDashboard(status, csrfToken);
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
                Port = _options.TunnelV3.Port, Enabled = _options.TunnelV3.Enabled,
                ConnectedClients = _tunnelV3.ConnectedClients, ReservedSlots = 0,
                UniqueIps = _tunnelV3.UniqueIpCount, Maintenance = _tunnelV3.IsMaintenanceMode
            } : null,
            TunnelV2 = _tunnelV2 != null ? new TunnelInfo
            {
                Port = _options.TunnelV2.Port, Enabled = _options.TunnelV2.Enabled,
                ConnectedClients = _tunnelV2.ConnectedClients, ReservedSlots = _tunnelV2.ReservedSlots,
                UniqueIps = _tunnelV2.UniqueIpCount, Maintenance = _tunnelV2.IsMaintenanceMode
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

    private string BuildHtmlDashboard(ServerStatus status, string csrfToken)
    {
        var sb = new StringBuilder();

        sb.AppendLine("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta http-equiv="refresh" content="5">
                <title>CnCNet Tunnel Server</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee;
                           min-height: 100vh; padding: 20px; }
                    .header { text-align: center; margin-bottom: 30px; }
                    .header h1 { color: #00d4ff; font-size: 2rem; margin-bottom: 5px; }
                    .header .info { color: #888; font-size: 0.9rem; }
                    .logout-btn { position: absolute; top: 20px; right: 20px; background: #0f3460;
                                  color: #888; border: 1px solid #0f3460; padding: 8px 16px;
                                  border-radius: 6px; cursor: pointer; text-decoration: none; }
                    .logout-btn:hover { background: #ff4444; color: #fff; border-color: #ff4444; }
                    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                            gap: 20px; max-width: 1400px; margin: 0 auto; }
                    .card { background: #16213e; border-radius: 12px; padding: 20px; border: 1px solid #0f3460; }
                    .card.log-card { grid-column: span 3; }
                    @media (max-width: 1000px) { .card.log-card { grid-column: 1 / -1; } }
                    .card h2 { color: #00d4ff; font-size: 1.1rem; margin-bottom: 15px;
                               padding-bottom: 10px; border-bottom: 1px solid #0f3460; }
                    .stat { display: flex; justify-content: space-between; align-items: center;
                            padding: 8px 0; border-bottom: 1px solid #0f3460; }
                    .stat:last-child { border-bottom: none; }
                    .stat-label { color: #888; }
                    .stat-value { color: #00ff88; font-weight: 600; }
                    .status-ok { color: #00ff88; }
                    .status-maint { color: #ffaa00; }
                    .status-disabled { color: #ff4444; }
                    .warning { color: #ffaa00; }
                    .danger { color: #ff4444; }
                    .toggle-row { display: flex; justify-content: space-between; align-items: center;
                                  padding: 10px 0; border-bottom: 1px solid #0f3460; }
                    .toggle-row:last-child { border-bottom: none; }
                    .toggle-label { color: #888; }
                    .toggle-switch { position: relative; width: 50px; height: 26px; }
                    .toggle-switch input { opacity: 0; width: 0; height: 0; }
                    .toggle-slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0;
                                     bottom: 0; background-color: #ff4444; transition: .3s; border-radius: 26px; }
                    .toggle-slider:before { position: absolute; content: ""; height: 20px; width: 20px;
                                            left: 3px; bottom: 3px; background-color: white;
                                            transition: .3s; border-radius: 50%; }
                    input:checked + .toggle-slider { background-color: #00ff88; }
                    input:checked + .toggle-slider:before { transform: translateX(24px); }
                    .limit-input { width: 70px; padding: 5px 8px; border: 1px solid #0f3460;
                                   border-radius: 6px; background: #1a1a2e; color: #00ff88;
                                   font-size: 14px; font-weight: 600; text-align: center;
                                   -moz-appearance: textfield; }
                    .limit-input::-webkit-outer-spin-button,
                    .limit-input::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
                    .limit-input:focus { outline: none; border-color: #00d4ff; }
                    .log-container { max-height: 400px; overflow-y: auto; font-family: monospace;
                                     font-size: 12px; background: #0d1321; border-radius: 6px; padding: 10px; }
                    .log-entry { padding: 3px 0; border-bottom: 1px solid #1a1a2e; }
                    .log-time { color: #666; }
                    .log-info { color: #00d4ff; } .log-warning { color: #ffaa00; }
                    .log-error { color: #ff4444; } .log-fatal { color: #ff0000; font-weight: bold; }
                    .log-debug { color: #888; } .log-verbose { color: #666; }
                    .blocked-list { max-height: 200px; overflow-y: auto; }
                    .blocked-ip { display: flex; justify-content: space-between; align-items: center;
                                  padding: 8px 0; border-bottom: 1px solid #0f3460; }
                    .blocked-ip:last-child { border-bottom: none; }
                    .unblock-btn { background: #ff4444; color: #fff; border: none; padding: 4px 10px;
                                   border-radius: 4px; cursor: pointer; font-size: 12px; }
                    .unblock-btn:hover { background: #ff6666; }
                    .maint-btn { padding: 6px 12px; border: 1px solid #0f3460; border-radius: 6px;
                                 cursor: pointer; font-size: 12px; transition: all 0.3s; }
                    .maint-btn.active { background: #ffaa00; color: #1a1a2e; border-color: #ffaa00; }
                    .maint-btn.inactive { background: #16213e; color: #888; }
                    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 0.8rem; }
                    .footer .signature { color: #ff6699; margin-top: 5px; }
                </style>
            </head>
            <body>
            """);

        // CSRF token as a JS constant – used in all fetch() calls
        var escapedCsrf = HttpUtility.JavaScriptStringEncode(csrfToken);
        sb.AppendLine($"    <script>const CSRF = '{escapedCsrf}';</script>");

        sb.AppendLine("    <a href=\"/logout\" class=\"logout-btn\">Logout</a>");
        sb.AppendLine($"""
                <div class="header">
                    <h1>CnCNet Tunnel Server</h1>
                    <div class="info">{HttpUtility.HtmlEncode(status.Server.Name)} | Uptime: {HttpUtility.HtmlEncode(status.Server.Uptime)}</div>
                </div>
                <div class="grid">
            """);

        // Tunnel V3 Card
        if (status.TunnelV3 != null)
        {
            var (v3Status, v3Icon, v3Class) = status.TunnelV3.Maintenance
                ? ("Maintenance", "&#128295;", "status-maint")
                : status.TunnelV3.Enabled ? ("Online", "&#9989;", "status-ok") : ("Offline", "&#10060;", "status-disabled");
            var v3MaintClass = status.TunnelV3.Maintenance ? "active" : "inactive";

            sb.AppendLine($"""
                    <div class="card">
                        <h2>&#128225; Tunnel V3 (Port {status.TunnelV3.Port})</h2>
                        <div class="stat"><span class="stat-label">Status</span>
                            <span class="stat-value {v3Class}">{v3Icon} {v3Status}</span></div>
                        <div class="stat"><span class="stat-label">Connected Clients</span>
                            <span class="stat-value">{status.TunnelV3.ConnectedClients} / {status.Server.MaxClients}</span></div>
                        <div class="stat"><span class="stat-label">Unique IPs</span>
                            <span class="stat-value">{status.TunnelV3.UniqueIps}</span></div>
                        <div class="stat"><span class="stat-label">Maintenance Mode</span>
                            <button class="maint-btn {v3MaintClass}" onclick="postAction('/maintenance/v3')">{(status.TunnelV3.Maintenance ? "ON" : "OFF")}</button></div>
                    </div>
                """);
        }

        // Tunnel V2 Card
        if (status.TunnelV2 != null)
        {
            var (v2Status, v2Icon, v2Class) = status.TunnelV2.Maintenance
                ? ("Maintenance", "&#128295;", "status-maint")
                : status.TunnelV2.Enabled ? ("Online", "&#9989;", "status-ok") : ("Offline", "&#10060;", "status-disabled");
            var v2MaintClass = status.TunnelV2.Maintenance ? "active" : "inactive";

            sb.AppendLine($"""
                    <div class="card">
                        <h2>&#128225; Tunnel V2 (Port {status.TunnelV2.Port})</h2>
                        <div class="stat"><span class="stat-label">Status</span>
                            <span class="stat-value {v2Class}">{v2Icon} {v2Status}</span></div>
                        <div class="stat"><span class="stat-label">Reserved Slots</span>
                            <span class="stat-value">{status.TunnelV2.ReservedSlots} / {status.Server.MaxClients}</span></div>
                        <div class="stat"><span class="stat-label">Unique IPs</span>
                            <span class="stat-value">{status.TunnelV2.UniqueIps}</span></div>
                        <div class="stat"><span class="stat-label">Maintenance Mode</span>
                            <button class="maint-btn {v2MaintClass}" onclick="postAction('/maintenance/v2')">{(status.TunnelV2.Maintenance ? "ON" : "OFF")}</button></div>
                    </div>
                """);
        }

        // Security Card
        var v3ValidationChecked = status.Security.V3PacketValidation ? "checked" : "";
        var v3DDoSChecked = status.Security.V3DDoSProtection ? "checked" : "";
        var v2DDoSChecked = status.Security.V2DDoSProtection ? "checked" : "";

        sb.AppendLine($"""
                <div class="card">
                    <h2>&#128737; Security</h2>
                    <div class="toggle-row"><span class="toggle-label">V3 Packet Validation</span>
                        <label class="toggle-switch"><input type="checkbox" {v3ValidationChecked} onchange="postAction('/toggle/v3validation')">
                        <span class="toggle-slider"></span></label></div>
                    <div class="toggle-row"><span class="toggle-label">V3 DDoS Protection</span>
                        <label class="toggle-switch"><input type="checkbox" {v3DDoSChecked} onchange="postAction('/toggle/v3ddos')">
                        <span class="toggle-slider"></span></label></div>
                    <div class="toggle-row"><span class="toggle-label">V2 DDoS Protection</span>
                        <label class="toggle-switch"><input type="checkbox" {v2DDoSChecked} onchange="postAction('/toggle/v2ddos')">
                        <span class="toggle-slider"></span></label></div>
                    <div class="stat"><span class="stat-label">Tracked IPs</span>
                        <span class="stat-value">{status.Security.TrackedIps}</span></div>
                    <div class="stat"><span class="stat-label">Local Blacklist</span>
                        <span class="stat-value {(status.Security.LocalBlacklist > 0 ? "warning" : "")}">{status.Security.LocalBlacklist}</span></div>
                    <div class="stat"><span class="stat-label">External Blacklist</span>
                        <span class="stat-value">{status.Security.ExternalBlacklist}</span></div>
                </div>
            """);

        // Configuration Card
        sb.AppendLine($"""
                <div class="card">
                    <h2>&#9881; Configuration</h2>
                    <div class="stat"><span class="stat-label">Max Clients</span>
                        <span class="stat-value">{_options.Server.MaxClients}</span></div>
                    <div class="stat"><span class="stat-label">IP Limit V3 (max 40)</span>
                        <input type="number" class="limit-input" value="{_options.TunnelV3.IpLimit}" min="1" max="40"
                               onkeydown="if(event.key==='Enter')postAction('/setlimit/v3/'+this.value)"></div>
                    <div class="stat"><span class="stat-label">IP Limit V2 (max 40)</span>
                        <input type="number" class="limit-input" value="{_options.TunnelV2.IpLimit}" min="1" max="40"
                               onkeydown="if(event.key==='Enter')postAction('/setlimit/v2/'+this.value)"></div>
                    <div class="stat"><span class="stat-label">Blacklist Duration (hours)</span>
                        <input type="number" class="limit-input" value="{_options.Security.IpBlacklistDurationHours}" min="1" max="168"
                               onkeydown="if(event.key==='Enter')postAction('/setblacklistduration/'+this.value)"></div>
                    <div class="stat"><span class="stat-label">Client Timeout</span>
                        <span class="stat-value">{_options.Server.ClientTimeout}s</span></div>
                    <div class="stat"><span class="stat-label">P2P/STUN</span>
                        <span class="stat-value {(_options.PeerToPeer.Enabled ? "status-ok" : "status-disabled")}">{(_options.PeerToPeer.Enabled ? "Enabled" : "Disabled")}</span></div>
                </div>
            """);

        // Blocked IPs Card
        var blockedIps = _securityManager.GetBlockedIps().ToList();
        sb.AppendLine("<div class=\"card\"><h2>&#128683; Blocked IPs (Local)</h2>");
        if (blockedIps.Count == 0)
        {
            sb.AppendLine("<div class=\"stat\"><span class=\"stat-label\">No IPs currently blocked</span></div>");
        }
        else
        {
            sb.AppendLine("<div class=\"blocked-list\">");
            foreach (var ip in blockedIps)
            {
                var encodedIp = HttpUtility.UrlEncode(ip.IpAddress);
                sb.AppendLine($"""
                            <div class="blocked-ip">
                                <span><span class="danger">{HttpUtility.HtmlEncode(ip.IpAddress)}</span>
                                <span class="stat-label">({ip.RemainingMinutes} min)</span></span>
                                <button class="unblock-btn" onclick="postAction('/unblock/{encodedIp}')">Unblock</button>
                            </div>
                    """);
            }
            sb.AppendLine("</div>");
        }
        sb.AppendLine("</div>");

        // Log Card
        var logEntries = InMemoryLogSink.Instance.GetEntries().ToList();
        sb.AppendLine("""
                <div class="card log-card">
                    <h2>&#128196; Recent Log Messages (last 50)</h2>
                    <div class="log-container">
            """);
        if (logEntries.Count == 0)
        {
            sb.AppendLine("<div class=\"log-entry\">No log entries yet</div>");
        }
        else
        {
            foreach (var entry in logEntries)
            {
                sb.AppendLine($"""
                            <div class="log-entry">
                                <span class="log-time">[{entry.Timestamp:HH:mm:ss}]</span>
                                <span class="{HttpUtility.HtmlEncode(entry.LevelClass)}">[{HttpUtility.HtmlEncode(entry.Level)}]</span>
                                {HttpUtility.HtmlEncode(entry.Message)}
                            </div>
                    """);
            }
        }
        sb.AppendLine("    </div></div>");

        // Footer + CSRF-aware JavaScript
        sb.AppendLine("""
                </div>
                <div class="footer">
                    CnCNet Tunnel Server v4.1 | Auto-refresh every 5 seconds
                    <div class="signature">made with love by Rowtag</div>
                </div>
                <script>
                    // All state-changing actions are POST with CSRF token header
                    function postAction(path) {
                        fetch(path, {
                            method: 'POST',
                            headers: { 'X-CSRF-Token': CSRF }
                        }).then(r => {
                            if (!r.ok) alert('Action failed: ' + r.status);
                        }).catch(e => alert('Network error: ' + e));
                    }
                </script>
            </body>
            </html>
            """);

        return sb.ToString();
    }

    private static string FormatUptime(TimeSpan uptime)
    {
        if (uptime.TotalDays >= 1) return $"{(int)uptime.TotalDays}d {uptime.Hours}h {uptime.Minutes}m";
        if (uptime.TotalHours >= 1) return $"{uptime.Hours}h {uptime.Minutes}m {uptime.Seconds}s";
        return $"{uptime.Minutes}m {uptime.Seconds}s";
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
