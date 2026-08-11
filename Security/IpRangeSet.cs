namespace CnCNetServer.Security;

/// <summary>
/// An immutable set of IPv4 addresses, stored as sorted non-overlapping ranges and queried by
/// binary search.
/// </summary>
/// <remarks>
/// The external blacklists total thousands of entries and are consulted on every inbound
/// packet - the exact workload a flood produces - so lookups must not scale with list size.
/// Individual addresses are folded in as /32 ranges, letting one binary search cover both kinds of
/// entry. Instances are built once per refresh and never mutated, so they are safe to publish to
/// readers with a single reference assignment.
/// </remarks>
internal sealed class IpRangeSet
{
    private readonly uint[] _starts;
    private readonly uint[] _ends;

    public static IpRangeSet Empty { get; } = new([], [], 0, 0);

    private IpRangeSet(uint[] starts, uint[] ends, int addressCount, int networkCount)
    {
        _starts = starts;
        _ends = ends;
        AddressCount = addressCount;
        NetworkCount = networkCount;
    }

    /// <summary>Number of single addresses that went into this set, for reporting.</summary>
    public int AddressCount { get; }

    /// <summary>Number of CIDR networks that went into this set, for reporting.</summary>
    public int NetworkCount { get; }

    /// <summary>Number of ranges actually stored, after overlapping entries were merged.</summary>
    public int RangeCount => _starts.Length;

    /// <summary>
    /// Builds a set from raw inclusive ranges, sorting and merging them so lookups can binary
    /// search. Overlapping and adjacent ranges are combined, which matters because the blacklist
    /// sources overlap heavily with one another.
    /// </summary>
    public static IpRangeSet Build(List<(uint Start, uint End)> ranges, int addressCount, int networkCount)
    {
        if (ranges.Count == 0)
            return Empty;

        ranges.Sort(static (a, b) => a.Start.CompareTo(b.Start));

        var starts = new List<uint>(ranges.Count);
        var ends = new List<uint>(ranges.Count);

        var currentStart = ranges[0].Start;
        var currentEnd = ranges[0].End;

        for (var i = 1; i < ranges.Count; i++)
        {
            var (start, end) = ranges[i];

            // Merge when this range overlaps the one being built, or butts directly against it.
            // The MaxValue guard keeps the adjacency test from wrapping around to zero.
            if (start <= currentEnd || (currentEnd < uint.MaxValue && start == currentEnd + 1))
            {
                if (end > currentEnd)
                    currentEnd = end;

                continue;
            }

            starts.Add(currentStart);
            ends.Add(currentEnd);
            currentStart = start;
            currentEnd = end;
        }

        starts.Add(currentStart);
        ends.Add(currentEnd);

        return new IpRangeSet([.. starts], [.. ends], addressCount, networkCount);
    }

    /// <summary>
    /// Whether the set contains an address. Allocation-free and O(log n).
    /// </summary>
    public bool Contains(uint address)
    {
        var starts = _starts;
        if (starts.Length == 0)
            return false;

        // Find the last range that begins at or below the address; it is the only one that can
        // contain it, because the ranges are sorted and non-overlapping.
        var index = Array.BinarySearch(starts, address);
        if (index < 0)
        {
            index = ~index - 1;
            if (index < 0)
                return false;
        }

        return address <= _ends[index];
    }

    /// <summary>
    /// Converts an IPv4 address to its numeric form. Returns false for anything that is not IPv4;
    /// the tunnel and STUN sockets are all opened as <see cref="System.Net.Sockets.AddressFamily.InterNetwork"/>,
    /// so in practice this only guards against a caller passing something unexpected.
    /// </summary>
    public static bool TryGetKey(System.Net.IPAddress address, out uint key)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            key = 0;
            return false;
        }

        Span<byte> bytes = stackalloc byte[4];
        if (!address.TryWriteBytes(bytes, out _))
        {
            key = 0;
            return false;
        }

        key = FromBytes(bytes);
        return true;
    }

    /// <summary>Reads four big-endian bytes as an IPv4 address in numeric form.</summary>
    public static uint FromBytes(ReadOnlySpan<byte> bytes)
        => ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];

    /// <summary>Renders a numeric IPv4 address back to dotted-quad form, for logs and the dashboard.</summary>
    public static string ToDisplayString(uint address)
        => $"{(address >> 24) & 0xFF}.{(address >> 16) & 0xFF}.{(address >> 8) & 0xFF}.{address & 0xFF}";
}
