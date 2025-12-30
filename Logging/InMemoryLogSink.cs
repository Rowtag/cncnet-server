using System.Collections.Concurrent;
using Serilog.Core;
using Serilog.Events;

namespace CnCNetServer.Logging;

/// <summary>
/// In-memory log sink that keeps recent log entries for display in the web dashboard.
/// Thread-safe for concurrent access. Old entries are removed when max count is reached.
/// </summary>
public sealed class InMemoryLogSink : ILogEventSink
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();
    private readonly int _maxEntries;

    /// <summary>
    /// Singleton instance for global access (1000 entries max).
    /// </summary>
    public static InMemoryLogSink Instance { get; } = new(1000);

    /// <summary>
    /// Current display filter level. Entries below this level are hidden (not deleted).
    /// </summary>
    public LogEventLevel DisplayLevel { get; set; } = LogEventLevel.Information;

    /// <summary>
    /// Current display limit for entries shown in UI.
    /// </summary>
    public int DisplayLimit { get; set; } = 50;

    /// <summary>
    /// Current view mode for the log panel (logs, v3sessions, v2sessions).
    /// </summary>
    public string DisplayView { get; set; } = "logs";

    public InMemoryLogSink(int maxEntries = 1000)
    {
        _maxEntries = maxEntries;
    }

    public void Emit(LogEvent logEvent)
    {
        var entry = new LogEntry
        {
            Timestamp = logEvent.Timestamp.LocalDateTime,
            TimestampUtc = logEvent.Timestamp.UtcDateTime,
            Level = logEvent.Level.ToString(),
            LevelValue = (int)logEvent.Level,
            Message = logEvent.RenderMessage(),
            LevelClass = GetLevelClass(logEvent.Level)
        };

        _entries.Enqueue(entry);

        // Remove oldest entries when max count is exceeded
        while (_entries.Count > _maxEntries)
        {
            _entries.TryDequeue(out _);
        }
    }

    /// <summary>
    /// Gets the most recent log entries filtered by current DisplayLevel and limited by DisplayLimit.
    /// </summary>
    public IEnumerable<LogEntry> GetEntries()
    {
        var minLevel = (int)DisplayLevel;
        return _entries
            .Where(e => e.LevelValue >= minLevel)
            .Reverse()
            .Take(DisplayLimit)
            .ToList();
    }

    /// <summary>
    /// Gets available display limits for UI dropdown.
    /// </summary>
    public static IEnumerable<int> GetAvailableLimits()
    {
        yield return 50;
        yield return 100;
        yield return 200;
        yield return 500;
        yield return 1000;
    }

    /// <summary>
    /// Gets all available log levels for UI dropdown.
    /// </summary>
    public static IEnumerable<(string Name, int Value)> GetAvailableLevels()
    {
        yield return ("Verbose", (int)LogEventLevel.Verbose);
        yield return ("Debug", (int)LogEventLevel.Debug);
        yield return ("Information", (int)LogEventLevel.Information);
        yield return ("Warning", (int)LogEventLevel.Warning);
        yield return ("Error", (int)LogEventLevel.Error);
    }

    private static string GetLevelClass(LogEventLevel level) => level switch
    {
        LogEventLevel.Verbose => "log-verbose",
        LogEventLevel.Debug => "log-debug",
        LogEventLevel.Information => "log-info",
        LogEventLevel.Warning => "log-warning",
        LogEventLevel.Error => "log-error",
        LogEventLevel.Fatal => "log-fatal",
        _ => "log-info"
    };
}

/// <summary>
/// A single log entry for display.
/// </summary>
public sealed class LogEntry
{
    public DateTime Timestamp { get; init; }
    public DateTime TimestampUtc { get; init; }
    public required string Level { get; init; }
    public int LevelValue { get; init; }
    public required string Message { get; init; }
    public required string LevelClass { get; init; }
}
