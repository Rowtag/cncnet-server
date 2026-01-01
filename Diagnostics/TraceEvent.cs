namespace CnCNetServer.Diagnostics;

/// <summary>
/// Trace level for filtering events by importance.
/// </summary>
public enum TraceLevel
{
    /// <summary>All events including successful packet relays (very verbose).</summary>
    Verbose,
    /// <summary>Important events: errors, blocks, timeouts, registrations (default).</summary>
    Important,
    /// <summary>Only errors and warnings.</summary>
    ErrorsOnly
}

/// <summary>
/// Tunnel source for filtering events by origin.
/// </summary>
public enum TunnelSource
{
    /// <summary>Unknown or shared source (e.g., security manager).</summary>
    Unknown,
    /// <summary>V3 Tunnel events.</summary>
    V3,
    /// <summary>V2 Tunnel events.</summary>
    V2
}

/// <summary>
/// Types of events that can be traced for connection diagnostics.
/// </summary>
public enum TraceEventType
{
    // General
    TracingStarted,
    TracingStopped,

    // Connection events
    // UNUSED: Reserved for future detailed connection tracing
    // ConnectionAttempt,
    // ConnectionAccepted,
    ConnectionRejected,
    ConnectionTimeout,
    // UNUSED: Reserved for future disconnect tracking
    // Disconnected,

    // Security events
    BlockedByLocalBlacklist,
    BlockedByExternalBlacklist,
    BlockedByRateLimit,
    BlockedByIpLimit,
    AddedToBlacklist,

    // V3 Tunnel events
    // UNUSED: Reserved for verbose packet-level tracing
    // V3PacketReceived,
    V3PacketRelayed,
    V3PingReceived,
    V3PingResponse,
    V3Registration,
    V3SessionTakeover,

    // V2 Tunnel events
    // UNUSED: Reserved for verbose packet-level tracing
    // V2PacketReceived,
    V2PacketRelayed,
    V2PingReceived,
    V2PingResponse,
    V2SlotAllocated,
    V2EndpointAssigned,

    // Error events
    SendFailed,
    InvalidPacket
}

/// <summary>
/// A single trace event for connection diagnostics.
/// </summary>
public sealed class TraceEvent
{
    public DateTime Timestamp { get; init; }
    public required string IpAddress { get; init; }
    public int? Port { get; init; }
    public TraceEventType EventType { get; init; }
    public required string Details { get; init; }
    public TunnelSource Source { get; init; } = TunnelSource.Unknown;

    /// <summary>
    /// Gets a CSS class for styling based on event type.
    /// </summary>
    public string CssClass => EventType switch
    {
        TraceEventType.TracingStarted or TraceEventType.TracingStopped => "trace-info",
        TraceEventType.V3Registration or TraceEventType.V2SlotAllocated => "trace-success",
        TraceEventType.ConnectionRejected or TraceEventType.BlockedByLocalBlacklist or
        TraceEventType.BlockedByExternalBlacklist or TraceEventType.BlockedByRateLimit or
        TraceEventType.BlockedByIpLimit or TraceEventType.AddedToBlacklist => "trace-blocked",
        TraceEventType.ConnectionTimeout => "trace-warning",
        TraceEventType.SendFailed or TraceEventType.InvalidPacket => "trace-error",
        _ => "trace-default"
    };

    /// <summary>
    /// Gets a human-readable event type name.
    /// </summary>
    public string EventTypeName => EventType switch
    {
        TraceEventType.TracingStarted => "Tracing Started",
        TraceEventType.TracingStopped => "Tracing Stopped",
        TraceEventType.ConnectionRejected => "Connection Rejected",
        TraceEventType.ConnectionTimeout => "Connection Timeout",
        TraceEventType.BlockedByLocalBlacklist => "Blocked (Local Blacklist)",
        TraceEventType.BlockedByExternalBlacklist => "Blocked (External Blacklist)",
        TraceEventType.BlockedByRateLimit => "Blocked (Rate Limit)",
        TraceEventType.BlockedByIpLimit => "Blocked (IP Limit)",
        TraceEventType.AddedToBlacklist => "Added to Blacklist",
        TraceEventType.V3PacketRelayed => "V3 Packet Relayed",
        TraceEventType.V3PingReceived => "V3 Ping Received",
        TraceEventType.V3PingResponse => "V3 Ping Response",
        TraceEventType.V3Registration => "V3 Registration",
        TraceEventType.V3SessionTakeover => "V3 Session Takeover",
        TraceEventType.V2PacketRelayed => "V2 Packet Relayed",
        TraceEventType.V2PingReceived => "V2 Ping Received",
        TraceEventType.V2PingResponse => "V2 Ping Response",
        TraceEventType.V2SlotAllocated => "V2 Slot Allocated",
        TraceEventType.V2EndpointAssigned => "V2 Endpoint Assigned",
        TraceEventType.SendFailed => "Send Failed",
        TraceEventType.InvalidPacket => "Invalid Packet",
        _ => EventType.ToString()
    };

    /// <summary>
    /// Gets the trace level for this event type.
    /// </summary>
    public TraceLevel Level => EventType switch
    {
        // Errors - always shown
        TraceEventType.SendFailed or TraceEventType.InvalidPacket => TraceLevel.ErrorsOnly,

        // Important events - shown by default
        TraceEventType.ConnectionRejected or TraceEventType.ConnectionTimeout or
        TraceEventType.BlockedByLocalBlacklist or
        TraceEventType.BlockedByExternalBlacklist or TraceEventType.BlockedByRateLimit or
        TraceEventType.BlockedByIpLimit or TraceEventType.AddedToBlacklist or
        TraceEventType.V3Registration or TraceEventType.V3SessionTakeover or
        TraceEventType.V2SlotAllocated or TraceEventType.V2EndpointAssigned or
        TraceEventType.TracingStarted or TraceEventType.TracingStopped => TraceLevel.Important,

        // Verbose events - packet relays, pings, etc.
        _ => TraceLevel.Verbose
    };

    /// <summary>
    /// Checks if this event should be shown at the given trace level.
    /// </summary>
    public bool ShouldShow(TraceLevel filterLevel) => filterLevel switch
    {
        TraceLevel.Verbose => true,
        TraceLevel.Important => Level != TraceLevel.Verbose,
        TraceLevel.ErrorsOnly => Level == TraceLevel.ErrorsOnly,
        _ => true
    };
}
