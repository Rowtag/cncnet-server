using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;

namespace CnCNetServer.Diagnostics;

/// <summary>
/// Connection tracer for debugging connectivity issues.
/// Tracks all connection events for specific IP addresses.
///
/// REMOVAL INSTRUCTIONS:
/// To remove this feature completely:
/// 1. Delete this file (Diagnostics/ConnectionTracer.cs)
/// 2. Delete Diagnostics/TraceEvent.cs
/// 3. Remove "using CnCNetServer.Diagnostics;" from files that use it
/// 4. Remove ConnectionTracer.Instance.* calls from:
///    - TunnelV3.cs
///    - TunnelV2.cs
///    - IpSecurityManager.cs
///    - StatusWebServer.cs (trace UI section)
/// 5. Delete the Diagnostics folder
/// </summary>
public sealed class ConnectionTracer
{
    private readonly ConcurrentQueue<TraceEvent> _events = new();
    private readonly ConcurrentQueue<TraceEvent> _importantEvents = new();
    private readonly ConcurrentDictionary<string, bool> _tracedIps = new();
    private const int MaxEvents = 1000;
    private const int MaxImportantEvents = 500;
    private const int MaxTracedIps = 10;

    // File logging
    private string? _traceFilePath;
    private readonly object _fileLock = new();
    private StreamWriter? _traceFileWriter;

    /// <summary>
    /// Singleton instance for global access.
    /// </summary>
    public static ConnectionTracer Instance { get; } = new();

    /// <summary>
    /// Whether to trace ALL IP addresses (resource intensive, for debugging only).
    /// </summary>
    public bool TraceAllIps { get; set; }

    /// <summary>
    /// When TraceAllIps is true, this controls which events are captured.
    /// Verbose = all events (resource intensive), Important = only important events (efficient).
    /// </summary>
    public TraceLevel TraceAllLevel { get; set; } = TraceLevel.Verbose;

    /// <summary>
    /// Current trace level filter for display.
    /// </summary>
    public TraceLevel DisplayLevel { get; set; } = TraceLevel.Important;

    /// <summary>
    /// Whether tracing is currently enabled (any IP being traced or trace-all mode).
    /// </summary>
    public bool IsEnabled => TraceAllIps || !_tracedIps.IsEmpty;

    /// <summary>
    /// Gets the list of currently traced IP addresses.
    /// </summary>
    public IEnumerable<string> TracedIps => _tracedIps.Keys;


    /// <summary>
    /// Configures file logging for trace events.
    /// </summary>
    /// <param name="filePath">Absolute path to the trace file.</param>
    public void ConfigureFileLogging(string filePath)
    {
        lock (_fileLock)
        {
            _traceFilePath = filePath;

            // Ensure directory exists
            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // Open file for appending with auto-flush
            _traceFileWriter = new StreamWriter(filePath, append: true, Encoding.UTF8)
            {
                AutoFlush = true
            };

            // Write header
            _traceFileWriter.WriteLine($"# CnCNet Tunnel Server - IP Trace Log");
            _traceFileWriter.WriteLine($"# Started: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            _traceFileWriter.WriteLine($"# Format: [Timestamp] [Source] [EventType] IP:Port - Details");
            _traceFileWriter.WriteLine("#");
        }
    }

    /// <summary>
    /// Writes a trace event to the file if file logging is enabled.
    /// </summary>
    private void WriteToFile(TraceEvent traceEvent)
    {
        if (_traceFileWriter == null)
            return;

        lock (_fileLock)
        {
            if (_traceFileWriter == null)
                return;

            try
            {
                var portInfo = traceEvent.Port > 0 ? $":{traceEvent.Port}" : "";
                var line = $"[{traceEvent.Timestamp:yyyy-MM-dd HH:mm:ss.fff}] [{traceEvent.Source}] [{traceEvent.EventType}] {traceEvent.IpAddress}{portInfo} - {traceEvent.Details}";
                _traceFileWriter.WriteLine(line);
            }
            catch
            {
                // Ignore write errors to avoid disrupting the server
            }
        }
    }

    /// <summary>
    /// Closes the trace file writer.
    /// </summary>
    public void CloseFileLogging()
    {
        lock (_fileLock)
        {
            if (_traceFileWriter != null)
            {
                _traceFileWriter.WriteLine($"# Closed: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
                _traceFileWriter.Dispose();
                _traceFileWriter = null;
            }
        }
    }

    /// <summary>
    /// Starts tracing a specific IP address.
    /// </summary>
    /// <param name="ipAddress">The IP address to trace.</param>
    /// <returns>True if tracing started, false if invalid IP or limit reached.</returns>
    public bool StartTracing(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var address))
            return false;

        if (_tracedIps.Count >= MaxTracedIps)
            return false;

        _tracedIps[address.ToString()] = true;

        // Log that tracing started
        LogEvent(address, TraceEventType.TracingStarted, "Tracing started for this IP");

        return true;
    }

    /// <summary>
    /// Stops tracing a specific IP address.
    /// </summary>
    public bool StopTracing(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var address))
            return false;

        // Log that tracing stopped before removing
        if (_tracedIps.ContainsKey(address.ToString()))
        {
            LogEvent(address, TraceEventType.TracingStopped, "Tracing stopped for this IP");
        }

        _tracedIps.TryRemove(address.ToString(), out _);
        return true;
    }

    /// <summary>
    /// Stops tracing all IP addresses and clears all event buffers.
    /// </summary>
    public void StopAllTracing()
    {
        _tracedIps.Clear();
        _events.Clear();
        _importantEvents.Clear();
    }

    /// <summary>
    /// Checks if an IP address is being traced.
    /// </summary>
    public bool IsTraced(IPAddress address)
    {
        return TraceAllIps || _tracedIps.ContainsKey(address.ToString());
    }

    /// <summary>
    /// Logs a trace event for an IP address if it's being traced.
    /// Respects TraceAllLevel when TraceAllIps is enabled to save resources.
    /// PERFORMANCE: Early exit if tracing is completely disabled.
    /// </summary>
    public void LogEvent(IPAddress address, TraceEventType eventType, string details, TunnelSource source = TunnelSource.Unknown)
    {
        // PERFORMANCE: Quick check before any work - most common case when tracing is off
        if (!IsEnabled)
            return;

        if (!IsTraced(address))
            return;

        var traceEvent = new TraceEvent
        {
            Timestamp = DateTime.UtcNow,
            IpAddress = address.ToString(),
            EventType = eventType,
            Details = details,
            Source = source
        };

        // When TraceAllIps is on with Important level, skip verbose events entirely
        if (TraceAllIps && TraceAllLevel != TraceLevel.Verbose && !traceEvent.ShouldShow(TraceAllLevel))
            return;

        _events.Enqueue(traceEvent);

        // Also add to important events buffer if this is an important/error event
        if (traceEvent.Level != TraceLevel.Verbose)
        {
            _importantEvents.Enqueue(traceEvent);
            while (_importantEvents.Count > MaxImportantEvents)
            {
                _importantEvents.TryDequeue(out _);
            }
        }

        // Write to file if configured
        WriteToFile(traceEvent);

        // Trim old events
        while (_events.Count > MaxEvents)
        {
            _events.TryDequeue(out _);
        }
    }

    /// <summary>
    /// Logs a trace event with an endpoint (includes port info).
    /// Respects TraceAllLevel when TraceAllIps is enabled to save resources.
    /// PERFORMANCE: Early exit if tracing is completely disabled.
    /// </summary>
    public void LogEvent(IPEndPoint endPoint, TraceEventType eventType, string details, TunnelSource source = TunnelSource.Unknown)
    {
        // PERFORMANCE: Quick check before any work - most common case when tracing is off
        if (!IsEnabled)
            return;

        if (!IsTraced(endPoint.Address))
            return;

        var traceEvent = new TraceEvent
        {
            Timestamp = DateTime.UtcNow,
            IpAddress = endPoint.Address.ToString(),
            Port = endPoint.Port,
            EventType = eventType,
            Details = details,
            Source = source
        };

        // When TraceAllIps is on with Important level, skip verbose events entirely
        if (TraceAllIps && TraceAllLevel != TraceLevel.Verbose && !traceEvent.ShouldShow(TraceAllLevel))
            return;

        _events.Enqueue(traceEvent);

        // Also add to important events buffer if this is an important/error event
        if (traceEvent.Level != TraceLevel.Verbose)
        {
            _importantEvents.Enqueue(traceEvent);
            while (_importantEvents.Count > MaxImportantEvents)
            {
                _importantEvents.TryDequeue(out _);
            }
        }

        // Write to file if configured
        WriteToFile(traceEvent);

        while (_events.Count > MaxEvents)
        {
            _events.TryDequeue(out _);
        }
    }

    /// <summary>
    /// Gets all trace events, optionally filtered by IP, trace level, and tunnel source.
    /// When filtering by Important or ErrorsOnly level, uses the separate important events buffer
    /// which preserves up to 500 important events even when verbose events overflow.
    /// </summary>
    public IEnumerable<TraceEvent> GetEvents(string? filterIp = null, int limit = 100, TraceLevel? levelFilter = null, TunnelSource? sourceFilter = null)
    {
        var level = levelFilter ?? DisplayLevel;

        // Use the appropriate buffer based on filter level
        // If viewing Important or Errors, use the dedicated important events buffer
        var events = level == TraceLevel.Verbose
            ? _events.Reverse()
            : _importantEvents.Reverse();

        if (!string.IsNullOrEmpty(filterIp))
        {
            events = events.Where(e => e.IpAddress == filterIp);
        }

        // Apply level filter (still needed for ErrorsOnly to filter out Important)
        events = events.Where(e => e.ShouldShow(level));

        // Filter by tunnel source if specified
        if (sourceFilter.HasValue && sourceFilter.Value != TunnelSource.Unknown)
        {
            events = events.Where(e => e.Source == sourceFilter.Value || e.Source == TunnelSource.Unknown);
        }

        return events.Take(limit).ToList();
    }

    /// <summary>
    /// Gets event count, optionally filtered by tunnel source.
    /// Uses the appropriate buffer based on current DisplayLevel.
    /// </summary>
    public int GetEventCount(TunnelSource? sourceFilter = null)
    {
        // Use the appropriate buffer based on current display level
        var events = DisplayLevel == TraceLevel.Verbose ? _events : _importantEvents;

        if (!sourceFilter.HasValue || sourceFilter.Value == TunnelSource.Unknown)
        {
            return events.Count;
        }

        return events.Count(e => e.Source == sourceFilter.Value || e.Source == TunnelSource.Unknown);
    }

    /// <summary>
    /// Gets the event count for a specific IP.
    /// </summary>
    public int GetEventCount(string ipAddress)
    {
        // Use the appropriate buffer based on current display level
        var events = DisplayLevel == TraceLevel.Verbose ? _events : _importantEvents;
        return events.Count(e => e.IpAddress == ipAddress);
    }

    /// <summary>
    /// Gets the count of important events buffer.
    /// </summary>
    public int ImportantEventCount => _importantEvents.Count;
}
