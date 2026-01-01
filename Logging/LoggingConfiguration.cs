using CnCNetServer.Configuration;
using Serilog;
using Serilog.Events;

namespace CnCNetServer.Logging;

/// <summary>
/// Configures Serilog for cross-platform logging with file rotation and retention.
/// Works on both Windows and Linux without platform-specific dependencies.
/// </summary>
public static class LoggingConfiguration
{
    /// <summary>
    /// Creates a configured Serilog logger instance.
    /// </summary>
    /// <param name="options">Logging configuration options.</param>
    /// <param name="logFilePath">Optional additional log file path (from --logfile).</param>
    /// <returns>Configured ILogger instance.</returns>
    public static ILogger CreateLogger(LoggingOptions options, string? logFilePath = null)
    {
        // Parse minimum log level from configuration
        var minimumLevel = ParseLogLevel(options.MinimumLevel);

        // Ensure log directory exists (cross-platform path handling)
        var logDirectory = GetLogDirectory(options.LogDirectory);
        Directory.CreateDirectory(logDirectory);

        // Calculate rolling interval based on configuration
        var rollingInterval = options.RollingIntervalDays switch
        {
            1 => RollingInterval.Day,
            <= 7 => RollingInterval.Day,  // Use daily rolling for intervals up to 7 days
            _ => RollingInterval.Day
        };

        // Build Serilog configuration
        var loggerConfig = new LoggerConfiguration()
            .MinimumLevel.Is(minimumLevel)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("ThreadId", Environment.CurrentManagedThreadId)
            .WriteTo.Console(
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss} UTC] [{Level:u3}] {Message:lj}{NewLine}{Exception}",
                theme: Serilog.Sinks.SystemConsole.Themes.AnsiConsoleTheme.Code)
            .WriteTo.File(
                path: Path.Combine(logDirectory, "cncnet-.log"),
                rollingInterval: rollingInterval,
                retainedFileCountLimit: CalculateRetainedFileCount(options.RetentionDays, options.RollingIntervalDays),
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff} UTC] [{Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}",
                shared: true,
                flushToDiskInterval: TimeSpan.FromSeconds(1))
            .WriteTo.Sink(InMemoryLogSink.Instance);

        // Add additional log file if specified via --logfile
        if (!string.IsNullOrEmpty(logFilePath))
        {
            var absoluteLogPath = GetLogFilePath(logFilePath);
            loggerConfig.WriteTo.File(
                path: absoluteLogPath,
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff} UTC] [{Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}",
                shared: true,
                flushToDiskInterval: TimeSpan.FromSeconds(1));
        }

        return loggerConfig.CreateLogger();
    }

    /// <summary>
    /// Gets the absolute path for a log file (--logfile option).
    /// If relative, makes it relative to the application directory.
    /// </summary>
    private static string GetLogFilePath(string configuredPath)
    {
        if (!Path.IsPathRooted(configuredPath))
        {
            var appDirectory = AppContext.BaseDirectory;
            return Path.Combine(appDirectory, configuredPath);
        }
        return configuredPath;
    }

    /// <summary>
    /// Gets the absolute path to the log directory.
    /// Uses cross-platform path handling.
    /// </summary>
    private static string GetLogDirectory(string configuredPath)
    {
        // If path is relative, make it relative to the application directory
        if (!Path.IsPathRooted(configuredPath))
        {
            var appDirectory = AppContext.BaseDirectory;
            return Path.Combine(appDirectory, configuredPath);
        }
        return configuredPath;
    }

    /// <summary>
    /// Calculates the number of log files to retain based on retention days and rolling interval.
    /// </summary>
    private static int CalculateRetainedFileCount(int retentionDays, int rollingIntervalDays)
    {
        // Ensure we keep enough files to cover the retention period
        // For 2-day rolling with 15-day retention: 15 / 2 = 7.5, so keep 8 files
        var fileCount = (int)Math.Ceiling((double)retentionDays / rollingIntervalDays);
        return Math.Max(fileCount, 1);
    }

    /// <summary>
    /// Parses log level string to Serilog LogEventLevel.
    /// </summary>
    private static LogEventLevel ParseLogLevel(string level)
    {
        return level.ToLowerInvariant() switch
        {
            "verbose" => LogEventLevel.Verbose,
            "debug" => LogEventLevel.Debug,
            "information" or "info" => LogEventLevel.Information,
            "warning" or "warn" => LogEventLevel.Warning,
            "error" => LogEventLevel.Error,
            "fatal" => LogEventLevel.Fatal,
            _ => LogEventLevel.Information
        };
    }
}
