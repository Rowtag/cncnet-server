// =============================================================================
// CnCNet Tunnel Server v4.0
// =============================================================================
// A UDP relay server for Command & Conquer games on CnCNet.
//
// Based on the original CnCNet Tunnel Server:
// https://github.com/CnCNet/cncnet-server
//
// Contributors:
//   - FunkyFr3sh (https://github.com/FunkyFr3sh) - Original author
//   - GrantBartlett (https://github.com/GrantBartlett) - Contributor
//   - Rowtag (https://github.com/Starter2007) - v4.0 rewrite & modernization
//
// License: GPL-3.0
// =============================================================================

using System.CommandLine;
using System.Net;
using CnCNetServer.Configuration;
using CnCNetServer.Diagnostics;
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
///   --logfile           Write logs to file (relative to server directory)
///   --trace             Enable IP trace UI in web dashboard
///   --trace-all         Enable tracing of ALL connections from startup
///   --trace-file        Write IP trace events to file (relative to server directory)
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

        // Initialize logging (with optional --logfile)
        Log.Logger = LoggingConfiguration.CreateLogger(options.Logging, options.Diagnostics.LogFile);

        try
        {
            // Print startup banner
            PrintBanner();

            Log.Information("CnCNet Tunnel Server v4.0 starting...");
            Log.Information("Server name: {Name}", options.Server.Name);

            // Log file logging status
            if (!string.IsNullOrEmpty(options.Diagnostics.LogFile))
            {
                Log.Information("[LOGGING] Writing to file: {LogFile}", options.Diagnostics.LogFile);
            }

            // Print security status
            PrintSecurityStatus(options);

            // --trace enables the trace UI in the web dashboard
            // --trace-all additionally enables tracing of ALL IPs from startup
            // --trace-file enables file logging of trace events
            if (options.Diagnostics.TraceAllConnections)
            {
                Log.Information("[DIAGNOSTICS] Trace mode available in web dashboard");

                // Configure trace file logging if specified
                if (!string.IsNullOrEmpty(options.Diagnostics.TraceFile))
                {
                    var traceFilePath = GetAbsoluteFilePath(options.Diagnostics.TraceFile);
                    ConnectionTracer.Instance.ConfigureFileLogging(traceFilePath);
                    Log.Information("[DIAGNOSTICS] Writing trace events to: {TraceFile}", traceFilePath);
                }

                if (options.Diagnostics.TraceAllFromStart)
                {
                    ConnectionTracer.Instance.TraceAllIps = true;

                    // Set trace level based on --trace-important flag
                    if (options.Diagnostics.TraceImportantOnly)
                    {
                        ConnectionTracer.Instance.TraceAllLevel = TraceLevel.Important;
                        Log.Warning("[DIAGNOSTICS] Tracing important events only (--trace-important) - resource efficient");
                    }
                    else
                    {
                        ConnectionTracer.Instance.TraceAllLevel = TraceLevel.Verbose;
                        Log.Warning("[DIAGNOSTICS] Tracing ALL connections from startup (--trace-all or --trace-file)");
                    }
                }
            }

            // Create shared services with IPv4-only socket handler for master server compatibility
            var socketHandler = new SocketsHttpHandler
            {
                ConnectCallback = async (context, cancellationToken) =>
                {
                    // Force IPv4 DNS resolution for master server compatibility
                    var entry = await Dns.GetHostEntryAsync(context.DnsEndPoint.Host, System.Net.Sockets.AddressFamily.InterNetwork, cancellationToken);
                    var socket = new System.Net.Sockets.Socket(System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
                    socket.NoDelay = true;
                    try
                    {
                        await socket.ConnectAsync(entry.AddressList, context.DnsEndPoint.Port, cancellationToken);
                        return new System.Net.Sockets.NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }
            };
            using var httpClient = new HttpClient(socketHandler) { Timeout = TimeSpan.FromSeconds(10) };
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

            // Close trace file if it was opened
            ConnectionTracer.Instance.CloseFileLogging();

            return 0;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Server terminated unexpectedly");
            return 1;
        }
        finally
        {
            // Close trace file on error too
            ConnectionTracer.Instance.CloseFileLogging();
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

    /// <summary>
    /// Gets absolute file path, relative to application directory if not already absolute.
    /// </summary>
    private static string GetAbsoluteFilePath(string configuredPath)
    {
        if (!Path.IsPathRooted(configuredPath))
        {
            var appDirectory = AppContext.BaseDirectory;
            return Path.Combine(appDirectory, configuredPath);
        }
        return configuredPath;
    }
}
