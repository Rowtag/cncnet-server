using Microsoft.Extensions.Configuration;

namespace CnCNetServer.Configuration;

/// <summary>
/// Builds the application configuration from layered sources.
///
/// Priority (highest wins):
///   1. CLI arguments       -- quick overrides, passwords show a warning
///   2. Environment vars    -- recommended for production/Docker (prefix: CNCNET_)
///   3. appsettings.local.json -- local overrides
///   4. appsettings.json    -- base config
/// </summary>
public static class AppConfiguration
{
    private static readonly HashSet<string> PasswordArgNames =
        ["--maintpw", "--masterpw"];

    /// <summary>
    /// Builds the IConfiguration and returns whether passwords were passed via CLI.
    /// </summary>
    public static (IConfigurationRoot Config, bool HasPasswordInCli) Build(string[] args)
    {
        var hasPasswordInCli = args.Any(a => PasswordArgNames.Contains(a));
        var cliOverrides = ParseCliArgs(args);

        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .AddJsonFile("appsettings.local.json", optional: true, reloadOnChange: false)
            .AddEnvironmentVariables(prefix: "CNCNET_")
            .AddInMemoryCollection(cliOverrides)
            .Build();

        return (config, hasPasswordInCli);
    }

    /// <summary>
    /// Parses CLI arguments into a flat config dictionary (highest priority layer).
    /// All args are optional - they override specific values from the config files.
    /// </summary>
    private static Dictionary<string, string?> ParseCliArgs(string[] args)
    {
        var result = new Dictionary<string, string?>();

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            var next = i + 1 < args.Length ? args[i + 1] : null;
            var hasValue = next != null && !next.StartsWith('-');

            switch (arg)
            {
                // Server
                case "--name": case "-n":
                    if (hasValue) result["Server:Name"] = args[++i]; break;
                case "--maxclients": case "-m":
                    if (hasValue) result["Server:MaxClients"] = args[++i]; break;
                case "--timeout": case "-t":
                    if (hasValue) result["Server:ClientTimeout"] = args[++i]; break;

                // Tunnel V3
                case "--port": case "-p":
                    if (hasValue) result["TunnelV3:Port"] = args[++i]; break;
                case "--iplimit": case "-l":
                    if (hasValue) result["TunnelV3:IpLimit"] = args[++i]; break;

                // Tunnel V2
                case "--portv2":
                    if (hasValue) result["TunnelV2:Port"] = args[++i]; break;
                case "--iplimitv2":
                    if (hasValue) result["TunnelV2:IpLimit"] = args[++i]; break;

                // P2P
                case "--nop2p":
                    result["PeerToPeer:Enabled"] = "false"; break;

                // Master server
                case "--nomaster":
                    result["MasterServer:Enabled"] = "false"; break;
                case "--master":
                    if (hasValue) result["MasterServer:Url"] = args[++i]; break;
                case "--masterpw":
                    if (hasValue) result["MasterServer:Password"] = args[++i]; break;

                // Maintenance / passwords
                case "--maintpw":
                    if (hasValue) result["Maintenance:Password"] = args[++i]; break;

                // Web monitor
                case "--nostatus":
                    result["WebMonitor:Enabled"] = "false"; break;
                case "--statusport":
                    if (hasValue) result["WebMonitor:Port"] = args[++i]; break;

                // Logging
                case "--logdir":
                    if (hasValue) result["Logging:LogDirectory"] = args[++i]; break;
                case "--verbose": case "-v":
                    result["Logging:MinimumLevel"] = "Debug"; break;
            }
        }

        return result;
    }

    /// <summary>
    /// Prints the help text and returns true if --help was requested.
    /// </summary>
    public static bool HandleHelp(string[] args)
    {
        if (!args.Contains("--help") && !args.Contains("-h") && !args.Contains("-?"))
            return false;

        Console.WriteLine("""
            CnCNet Tunnel Server

            USAGE:
              cncnet-server [options]

            CONFIGURATION (priority: CLI > ENV > appsettings.local.json > appsettings.json):
              All options can be set in appsettings.local.json or via environment variables.
              CLI arguments override config file values.

            SERVER OPTIONS:
              --name, -n <name>         Server name shown in server list
              --maxclients, -m <n>      Maximum clients (default: 200)
              --timeout, -t <sec>       Client timeout in seconds (default: 60)

            TUNNEL OPTIONS:
              --port, -p <port>         V3 tunnel UDP port (default: 50001)
              --iplimit, -l <n>         Max clients per IP for V3 (default: 8)
              --portv2 <port>           V2 tunnel port (default: 50000)
              --iplimitv2 <n>           Max requests per IP for V2 (default: 4)
              --nop2p                   Disable STUN/P2P servers

            MASTER SERVER:
              --nomaster                Don't register to master server
              --master <url>            Master server URL
              --masterpw <pw>           Master server password
                                        [!] Use CNCNET_MASTERSERVER__PASSWORD env var instead

            MAINTENANCE:
              --maintpw <pw>            Web dashboard password
                                        [!] Use CNCNET_MAINTENANCE__PASSWORD env var instead

            WEB MONITOR:
              --nostatus                Disable web dashboard
              --statusport <port>       Web dashboard port (default: 1337)

            LOGGING:
              --logdir <path>           Log directory (default: logs)
              --verbose, -v             Enable debug logging

            ENVIRONMENT VARIABLES (recommended for passwords):
              CNCNET_SERVER__NAME
              CNCNET_SERVER__MAXCLIENTS
              CNCNET_MAINTENANCE__PASSWORD
              CNCNET_MASTERSERVER__PASSWORD
              CNCNET_TUNNELV3__PORT
              CNCNET_WEBMONITOR__PORT
              (use __ for nested keys, e.g. CNCNET_SERVER__NAME)

            EXAMPLES:
              # Run with config file (recommended):
              ./cncnet-server

              # Quick test without master registration:
              ./cncnet-server --name "TestServer" --nomaster

              # Production with env var for password:
              CNCNET_MAINTENANCE__PASSWORD=secret ./cncnet-server

              # Full override via CLI (not recommended for passwords):
              ./cncnet-server --name "MyServer" --maxclients 100 --maintpw secret

            CONFIG FILES:
              appsettings.json          Base configuration
              appsettings.local.json    Local overrides (server name, passwords)

            """);

        return true;
    }
}
