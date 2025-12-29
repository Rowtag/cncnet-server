using System.CommandLine;
using CnCNetServer.Configuration;
using CnCNetServer.Infrastructure;
using CnCNetServer.Logging;
using CnCNetServer.PeerToPeer;
using CnCNetServer.Security;
using CnCNetServer.Tunnels;
using Serilog;

namespace CnCNetServer;

/// <summary>
/// CnCNet Tunnel Server - UDP relay for Command & Conquer games.
///
/// Enables players behind NAT/firewall to play together by relaying
/// game packets through this server.
///
/// Features:
/// - V3 Tunnel: Modern UDP-based protocol (port 50001)
/// - V2 Tunnel: Legacy HTTP+UDP protocol (port 50000)
/// - STUN Server: P2P NAT traversal (ports 8054, 3478)
/// - Web Monitor: Status dashboard (port 1337)
/// - DDoS Protection: Rate limiting and IP blacklisting
/// - Cross-platform: Windows and Linux support
///
/// Usage:
///   CnCNetServer [options]
///
/// Options:
///   --name, -n          Server name (default: "Unnamed server")
///   --port, -p          V3 tunnel port (default: 50001)
///   --portv2            V2 tunnel port (default: 50000)
///   --maxclients, -m    Maximum clients (default: 200)
///   --iplimit, -l       Max clients per IP for V3 (default: 8)
///   --iplimitv2         Max requests per IP for V2 (default: 4)
///   --nomaster          Don't register to master server
///   --master            Master server URL
///   --masterpw          Master server password
///   --maintpw           Maintenance mode password
///   --nop2p             Disable P2P NAT traversal
///   --nostatus          Disable web status monitor
///   --statusport        Web status port (default: 1337)
///   --logdir            Log directory (default: "logs")
///   --verbose, -v       Enable verbose logging
///   --help, -h          Show help
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        // Parse command-line arguments
        var cliOptions = CommandLineOptions.Parse(args);

        // Handle --help (System.CommandLine handles this automatically, but we exit here)
        if (args.Contains("--help") || args.Contains("-h") || args.Contains("-?"))
        {
            var rootCommand = CommandLineOptions.BuildRootCommand();
            return await rootCommand.InvokeAsync(args);
        }

        // Convert CLI options to ServiceOptions
        var options = cliOptions.ToServiceOptions();

        // Initialize logging
        Log.Logger = LoggingConfiguration.CreateLogger(options.Logging);

        try
        {
            // Print startup banner
            PrintBanner();

            Log.Information("CnCNet Tunnel Server v4.0 starting...");
            Log.Information("Server name: {Name}", options.Server.Name);

            // Print security status
            PrintSecurityStatus(options);

            // Create shared services
            using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            using var securityManager = new IpSecurityManager(options.Security, Log.Logger);

            // Wait for initial external blacklist load
            if (options.Security.ExternalBlacklistUrls.Length > 0)
            {
                Log.Information("[SECURITY] Refreshing external IP blacklists...");
            }

            // Create tunnel services
            TunnelV3? tunnelV3 = null;
            TunnelV2? tunnelV2 = null;

            if (options.TunnelV3.Enabled)
            {
                tunnelV3 = new TunnelV3(options, securityManager, Log.Logger, httpClient);
            }

            if (options.TunnelV2.Enabled)
            {
                tunnelV2 = new TunnelV2(options, securityManager, Log.Logger, httpClient);
            }

            // Create STUN servers for P2P
            StunServer? stun1 = null;
            StunServer? stun2 = null;

            if (options.PeerToPeer.Enabled)
            {
                stun1 = new StunServer(options.PeerToPeer.StunPort1, securityManager, Log.Logger);
                stun2 = new StunServer(options.PeerToPeer.StunPort2, securityManager, Log.Logger);
            }

            // Create web monitor
            StatusWebServer? webServer = null;
            if (options.WebMonitor.Enabled)
            {
                webServer = new StatusWebServer(options, securityManager, tunnelV3, tunnelV2, Log.Logger);
            }

            // Setup graceful shutdown
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                Log.Information("Shutdown requested...");
                cts.Cancel();
            };

            // Start all services concurrently
            var tasks = new List<Task>();

            if (tunnelV3 != null)
                tasks.Add(tunnelV3.RunAsync(cts.Token));

            if (tunnelV2 != null)
                tasks.Add(tunnelV2.RunAsync(cts.Token));

            if (stun1 != null)
                tasks.Add(stun1.RunAsync(cts.Token));

            if (stun2 != null)
                tasks.Add(stun2.RunAsync(cts.Token));

            if (webServer != null)
                tasks.Add(webServer.RunAsync(cts.Token));

            // Print startup complete message
            PrintStartupComplete(options);

            // Wait for all services to complete (on shutdown)
            await Task.WhenAll(tasks);

            // Print final statistics
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

    /// <summary>
    /// Prints the startup banner.
    /// </summary>
    private static void PrintBanner()
    {
        Console.WriteLine();
        Console.WriteLine("  CnCNet Tunnel Server v4.0");
        Console.WriteLine("  https://cncnet.org");
        Console.WriteLine();
    }

    /// <summary>
    /// Prints security configuration status on startup.
    /// </summary>
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
    }

    /// <summary>
    /// Prints startup complete messages.
    /// </summary>
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
            Console.WriteLine($"  [STATUS] Web monitor on http://localhost:{options.WebMonitor.Port}");

        Console.WriteLine("───────────────────────────────────────────────────────────────");
        Console.WriteLine("  Press Ctrl+C to shutdown gracefully");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine();
    }

    /// <summary>
    /// Prints final statistics on shutdown.
    /// </summary>
    private static void PrintShutdownStats(IpSecurityManager securityManager)
    {
        var stats = securityManager.GetStatistics();
        Log.Information(
            "[STATS] Final: {Connections} connections, {LocalBlocked} local blacklisted, {ExternalBlocked} external blacklisted",
            stats.TotalConnections,
            stats.BlockedByLocalBlacklist,
            stats.BlockedByExternalBlacklist);
    }
}
