using System.CommandLine;
using System.CommandLine.Parsing;

namespace CnCNetServer.Configuration;

/// <summary>
/// Command-line options for the CnCNet tunnel server.
/// Provides the same options as the original server with modern parsing.
/// </summary>
public sealed class CommandLineOptions
{
    // Server options
    public string Name { get; set; } = "Unnamed server";
    public int MaxClients { get; set; } = 200;
    public int ClientTimeout { get; set; } = 60;

    // Tunnel V3 options
    public int Port { get; set; } = 50001;
    public int IpLimit { get; set; } = 8;

    // Tunnel V2 options
    public int PortV2 { get; set; } = 50000;
    public int IpLimitV2 { get; set; } = 4;

    // P2P options
    public bool NoP2P { get; set; }

    // Master server options
    public bool NoMaster { get; set; }
    public string Master { get; set; } = "http://cncnet.org/master-announce";
    public string MasterPassword { get; set; } = string.Empty;

    // Maintenance
    public string MaintenancePassword { get; set; } = string.Empty;

    // Web monitor
    public int StatusPort { get; set; } = 1337;
    public bool NoStatus { get; set; }

    // Logging
    public string LogDir { get; set; } = "logs";
    public bool Verbose { get; set; }

    // Option definitions (stored for parsing)
    private static readonly Option<string> NameOption = new(
        ["--name", "-n"], () => "Unnamed server",
        "Name of the server shown in server list");

    private static readonly Option<int> MaxClientsOption = new(
        ["--maxclients", "-m"], () => 200,
        "Maximum clients allowed on the tunnel server");

    private static readonly Option<int> TimeoutOption = new(
        ["--timeout", "-t"], () => 60,
        "Client timeout in seconds");

    private static readonly Option<int> PortOption = new(
        ["--port", "-p"], () => 50001,
        "Port used for the V3 tunnel server (UDP)");

    private static readonly Option<int> IpLimitOption = new(
        ["--iplimit", "-l"], () => 8,
        "Maximum clients allowed per IP address (V3)");

    private static readonly Option<int> PortV2Option = new(
        ["--portv2"], () => 50000,
        "Port used for the V2 tunnel server (HTTP + UDP)");

    private static readonly Option<int> IpLimitV2Option = new(
        ["--iplimitv2"], () => 4,
        "Maximum game requests allowed per IP address (V2)");

    private static readonly Option<bool> NoP2POption = new(
        ["--nop2p"], () => false,
        "Disable P2P NAT traversal ports (8054, 3478 UDP)");

    private static readonly Option<bool> NoMasterOption = new(
        ["--nomaster"], () => false,
        "Don't register to master server");

    private static readonly Option<string> MasterOption = new(
        ["--master"], () => "http://cncnet.org/master-announce",
        "Master server URL");

    private static readonly Option<string> MasterPwOption = new(
        ["--masterpw"], () => string.Empty,
        "Master server password");

    private static readonly Option<string> MaintPwOption = new(
        ["--maintpw"], () => string.Empty,
        "Maintenance mode password");

    private static readonly Option<int> StatusPortOption = new(
        ["--statusport"], () => 1337,
        "Port for the web status monitor");

    private static readonly Option<bool> NoStatusOption = new(
        ["--nostatus"], () => false,
        "Disable web status monitor");

    private static readonly Option<string> LogDirOption = new(
        ["--logdir"], () => "logs",
        "Directory for log files");

    private static readonly Option<bool> VerboseOption = new(
        ["--verbose", "-v"], () => false,
        "Enable verbose (debug) logging");

    /// <summary>
    /// Builds the System.CommandLine RootCommand with all options.
    /// </summary>
    public static RootCommand BuildRootCommand()
    {
        var rootCommand = new RootCommand("CnCNet Tunnel Server - UDP relay for Command & Conquer games");

        rootCommand.AddOption(NameOption);
        rootCommand.AddOption(MaxClientsOption);
        rootCommand.AddOption(TimeoutOption);
        rootCommand.AddOption(PortOption);
        rootCommand.AddOption(IpLimitOption);
        rootCommand.AddOption(PortV2Option);
        rootCommand.AddOption(IpLimitV2Option);
        rootCommand.AddOption(NoP2POption);
        rootCommand.AddOption(NoMasterOption);
        rootCommand.AddOption(MasterOption);
        rootCommand.AddOption(MasterPwOption);
        rootCommand.AddOption(MaintPwOption);
        rootCommand.AddOption(StatusPortOption);
        rootCommand.AddOption(NoStatusOption);
        rootCommand.AddOption(LogDirOption);
        rootCommand.AddOption(VerboseOption);

        return rootCommand;
    }

    /// <summary>
    /// Parses command-line arguments into CommandLineOptions.
    /// </summary>
    public static CommandLineOptions Parse(string[] args)
    {
        var rootCommand = BuildRootCommand();
        var parseResult = rootCommand.Parse(args);

        return new CommandLineOptions
        {
            Name = parseResult.GetValueForOption(NameOption) ?? "Unnamed server",
            MaxClients = parseResult.GetValueForOption(MaxClientsOption),
            ClientTimeout = parseResult.GetValueForOption(TimeoutOption),
            Port = parseResult.GetValueForOption(PortOption),
            IpLimit = parseResult.GetValueForOption(IpLimitOption),
            PortV2 = parseResult.GetValueForOption(PortV2Option),
            IpLimitV2 = parseResult.GetValueForOption(IpLimitV2Option),
            NoP2P = parseResult.GetValueForOption(NoP2POption),
            NoMaster = parseResult.GetValueForOption(NoMasterOption),
            Master = parseResult.GetValueForOption(MasterOption) ?? "http://cncnet.org/master-announce",
            MasterPassword = parseResult.GetValueForOption(MasterPwOption) ?? string.Empty,
            MaintenancePassword = parseResult.GetValueForOption(MaintPwOption) ?? string.Empty,
            StatusPort = parseResult.GetValueForOption(StatusPortOption),
            NoStatus = parseResult.GetValueForOption(NoStatusOption),
            LogDir = parseResult.GetValueForOption(LogDirOption) ?? "logs",
            Verbose = parseResult.GetValueForOption(VerboseOption)
        };
    }

    /// <summary>
    /// Converts command-line options to ServiceOptions.
    /// Applies validation and default value corrections.
    /// </summary>
    public ServiceOptions ToServiceOptions()
    {
        return new ServiceOptions
        {
            Server = new ServerOptions
            {
                Name = string.IsNullOrEmpty(Name) ? "Unnamed server" : Name.Replace(";", ""),
                MaxClients = MaxClients < 2 ? 200 : MaxClients,
                ClientTimeout = ClientTimeout < 10 ? 60 : ClientTimeout
            },
            TunnelV3 = new TunnelV3Options
            {
                Enabled = true,
                Port = Port <= 1024 ? 50001 : Port,
                IpLimit = IpLimit < 1 ? 8 : IpLimit
            },
            TunnelV2 = new TunnelV2Options
            {
                Enabled = true,
                Port = PortV2 <= 1024 ? 50000 : PortV2,
                IpLimit = IpLimitV2 < 1 ? 4 : IpLimitV2
            },
            PeerToPeer = new PeerToPeerOptions
            {
                Enabled = !NoP2P,
                StunPort1 = 8054,
                StunPort2 = 3478
            },
            MasterServer = new MasterServerOptions
            {
                Enabled = !NoMaster,
                Url = Master,
                Password = MasterPassword,
                AnnounceIntervalSeconds = 60
            },
            Maintenance = new MaintenanceOptions
            {
                Password = MaintenancePassword
            },
            Security = new SecurityOptions
            {
                IpBlacklistDurationHours = 24,
                MaxPingsPerIp = 20,
                MaxPingsGlobal = 5000
                // ExternalBlacklistUrls uses default from SecurityOptions
            },
            WebMonitor = new WebMonitorOptions
            {
                Enabled = !NoStatus,
                Port = StatusPort < 1 ? 1337 : StatusPort
            },
            Logging = new LoggingOptions
            {
                LogDirectory = LogDir,
                RetentionDays = 15,
                RollingIntervalDays = 2,
                MinimumLevel = Verbose ? "Debug" : "Information"
            }
        };
    }
}
