using Microsoft.Extensions.Configuration;
using CnCNetServer.Configuration;
using CnCNetServer.Infrastructure;
using CnCNetServer.Logging;
using CnCNetServer.PeerToPeer;
using CnCNetServer.Security;
using CnCNetServer.Tunnels;
using Serilog;

namespace CnCNetServer;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        // Handle --help before anything else
        if (AppConfiguration.HandleHelp(args))
            return 0;

        // Build layered configuration: appsettings.json → appsettings.local.json → ENV → CLI
        var (config, hasPasswordInCli) = AppConfiguration.Build(args);

        // Bind to strongly-typed options
        var options = new ServiceOptions();
        config.Bind(options);

        // Validate and sanitize options
        options.Server.Name = string.IsNullOrWhiteSpace(options.Server.Name)
            ? "Unnamed server"
            : options.Server.Name.Replace(";", "");
        options.Server.MaxClients = options.Server.MaxClients < 2 ? 200 : options.Server.MaxClients;
        options.Server.ClientTimeout = options.Server.ClientTimeout < 10 ? 60 : options.Server.ClientTimeout;
        options.TunnelV3.Port = options.TunnelV3.Port <= 1024 ? 50001 : options.TunnelV3.Port;
        options.TunnelV3.IpLimit = Math.Clamp(options.TunnelV3.IpLimit, 1, 40);
        options.TunnelV2.Port = options.TunnelV2.Port <= 1024 ? 50000 : options.TunnelV2.Port;
        options.TunnelV2.IpLimit = Math.Clamp(options.TunnelV2.IpLimit, 1, 40);
        options.WebMonitor.Port = options.WebMonitor.Port < 1 ? 1337 : options.WebMonitor.Port;

        // Initialize logging
        Log.Logger = LoggingConfiguration.CreateLogger(options.Logging);

        try
        {
            PrintBanner();
            Log.Information("CnCNet Tunnel Server v4.1 starting...");
            Log.Information("Server name: {Name}", options.Server.Name);

            // Warn if passwords were passed as CLI args (visible in process list)
            if (hasPasswordInCli)
            {
                Log.Warning("[SECURITY] Password(s) passed via CLI argument are visible in the process list (ps aux).");
                Log.Warning("[SECURITY] Recommended: use CNCNET_MAINTENANCE__PASSWORD / CNCNET_MASTERSERVER__PASSWORD");
                Log.Warning("[SECURITY] or set passwords in appsettings.local.json instead.");
            }

            PrintSecurityStatus(options);

            using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            using var securityManager = new IpSecurityManager(options.Security, Log.Logger);

            if (options.Security.ExternalBlacklistUrls.Length > 0)
                Log.Information("[SECURITY] Refreshing external IP blacklists...");

            TunnelV3? tunnelV3 = null;
            TunnelV2? tunnelV2 = null;

            if (options.TunnelV3.Enabled)
                tunnelV3 = new TunnelV3(options, securityManager, Log.Logger, httpClient);

            if (options.TunnelV2.Enabled)
                tunnelV2 = new TunnelV2(options, securityManager, Log.Logger, httpClient);

            StunServer? stun1 = null;
            StunServer? stun2 = null;

            if (options.PeerToPeer.Enabled)
            {
                stun1 = new StunServer(options.PeerToPeer.StunPort1, securityManager, Log.Logger);
                stun2 = new StunServer(options.PeerToPeer.StunPort2, securityManager, Log.Logger);
            }

            StatusWebServer? webServer = null;
            if (options.WebMonitor.Enabled)
                webServer = new StatusWebServer(options, securityManager, tunnelV3, tunnelV2, Log.Logger);

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                Log.Information("Shutdown requested...");
                cts.Cancel();
            };

            var tasks = new List<Task>();
            if (tunnelV3 != null) tasks.Add(tunnelV3.RunAsync(cts.Token));
            if (tunnelV2 != null) tasks.Add(tunnelV2.RunAsync(cts.Token));
            if (stun1 != null) tasks.Add(stun1.RunAsync(cts.Token));
            if (stun2 != null) tasks.Add(stun2.RunAsync(cts.Token));
            if (webServer != null) tasks.Add(webServer.RunAsync(cts.Token));

            PrintStartupComplete(options);
            await Task.WhenAll(tasks);
            PrintShutdownStats(securityManager);
            return 0;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Server terminated unexpectedly");
            return 1;
        }
        finally
        {
            await Log.CloseAndFlushAsync();
        }
    }

    private static void PrintBanner()
    {
        Console.WriteLine();
        Console.WriteLine("  CnCNet Tunnel Server v4.1");
        Console.WriteLine("  https://cncnet.org");
        Console.WriteLine();
    }

    private static void PrintSecurityStatus(ServiceOptions options)
    {
        Log.Information("[SECURITY] V3 DDoS protection: {Status}",
            options.TunnelV3.DDoSProtectionEnabled ? "ENABLED" : "DISABLED");
        Log.Information("[SECURITY] V3 Packet validation: {Status}",
            TunnelV3PacketValidation.Enabled ? "ENABLED" : "DISABLED");
        Log.Information("[SECURITY] V2 DDoS protection: {Status}",
            options.TunnelV2.DDoSProtectionEnabled ? "ENABLED" : "DISABLED");
        Log.Information("[SECURITY] IP blacklist duration: {Hours} hours",
            options.Security.IpBlacklistDurationHours);
        Log.Information("[SECURITY] External blacklists: {Count} sources",
            options.Security.ExternalBlacklistUrls.Length);
        Log.Information("[SECURITY] Web dashboard auth: {Status}",
            string.IsNullOrEmpty(options.Maintenance.Password) ? "DISABLED (no password set!)" : "ENABLED");
    }

    private static void PrintStartupComplete(ServiceOptions options)
    {
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("  CnCNet Tunnel Server is running");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        if (options.TunnelV3.Enabled)
            Console.WriteLine($"  [V3] UDP Tunnel on port {options.TunnelV3.Port}");
        if (options.TunnelV2.Enabled)
            Console.WriteLine($"  [V2] HTTP+UDP Tunnel on port {options.TunnelV2.Port}");
        if (options.PeerToPeer.Enabled)
            Console.WriteLine($"  [P2P] STUN servers on ports {options.PeerToPeer.StunPort1}, {options.PeerToPeer.StunPort2}");
        if (options.WebMonitor.Enabled)
            Console.WriteLine($"  [STATUS] Web monitor on port {options.WebMonitor.Port}");
        Console.WriteLine("───────────────────────────────────────────────────────────────");
        Console.WriteLine("  Press Ctrl+C to shutdown gracefully");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine();
    }

    private static void PrintShutdownStats(IpSecurityManager securityManager)
    {
        var stats = securityManager.GetStatistics();
        Log.Information(
            "[STATS] Final: {Connections} connections, {LocalBlocked} local blacklisted, {ExternalBlocked} external blacklisted",
            stats.TotalConnections, stats.BlockedByLocalBlacklist, stats.BlockedByExternalBlacklist);
    }
}
