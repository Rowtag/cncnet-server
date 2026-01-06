using System.Collections.Concurrent;
using Serilog.Core;
using Serilog.Events;

namespace CnCNetServer.Logging;

/// <summary>
/// In-memory log sink that keeps the last N log entries for display in the web dashboard.
/// Thread-safe for concurrent access.
/// </summary>
public sealed class InMemoryLogSink : ILogEventSink
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();
    private readonly int _maxEntries;

    /// <summary>
    /// Singleton instance for global access.
    /// </summary>
    public static InMemoryLogSink Instance { get; } = new(50);

    public InMemoryLogSink(int maxEntries = 50)
    {
        _maxEntries = maxEntries;
    }

    public void Emit(LogEvent logEvent)
    {
        var entry = new LogEntry
        {
            Timestamp = logEvent.Timestamp.LocalDateTime,
            Level = logEvent.Level.ToString(),
            Message = logEvent.RenderMessage(),
            LevelClass = GetLevelClass(logEvent.Level)
        };

        _entries.Enqueue(entry);

        // Keep only the last N entries
        while (_entries.Count > _maxEntries)
        {
            _entries.TryDequeue(out _);
        }
    }

    /// <summary>
    /// Gets the most recent log entries.
    /// </summary>
    public IEnumerable<LogEntry> GetEntries()
    {
        return _entries.Reverse().ToList();
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
    public required string Level { get; init; }
    public required string Message { get; init; }
    public required string LevelClass { get; init; }
}
