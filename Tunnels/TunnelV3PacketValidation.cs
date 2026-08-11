namespace CnCNetServer.Tunnels;

/// <summary>
/// Validates V3 tunnel packets against legitimate CnCNet protocol formats.
/// Helps protect against malformed/flooding packets.
/// </summary>
internal static class TunnelV3PacketValidation
{
    // Magic bytes for negotiation packets. Must match the client's V3TunnelCommunicator.
    private static readonly byte[] MagicBytes = "CNCNET"u8.ToArray();

    private const int HeaderSize = 8;
    private const int PingPacketSize = 50;
    private const int RegistrationPacketSize = 8;
    private const int MinNegotiationPacketSize = 15; // 8 (header) + 6 (magic) + 1 (type)

    // Smallest game data packet worth relaying: 8 (header) + 4, the minimum the client's game
    // bridge will forward. Anything smaller carries no addressable payload.
    private const int MinGameDataPacketSize = 12;

    /// <summary>
    /// Gets or sets whether packet validation is enabled.
    /// Can be toggled at runtime via the web dashboard.
    /// </summary>
    private static volatile bool _enabled = true;
    public static bool Enabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    /// <summary>
    /// Validates that a packet matches one of the legitimate V3 tunnel formats.
    /// </summary>
    /// <param name="buffer">The packet data buffer</param>
    /// <param name="size">The size of the received packet</param>
    /// <param name="senderId">The sender ID from packet header</param>
    /// <param name="receiverId">The receiver ID from packet header</param>
    /// <returns>True if packet is valid, false if it should be dropped</returns>
    public static bool IsValidPacket(ReadOnlySpan<byte> buffer, int size, uint senderId, uint receiverId)
    {
        if (!Enabled)
            return true;

        if (size < HeaderSize)
            return false;

        // Ping: senderId=0, receiverId=0, size=50
        if (senderId == 0 && receiverId == 0)
            return size == PingPacketSize;

        // Registration: senderId!=0, receiverId=0, size=8
        if (senderId != 0 && receiverId == 0)
            return size == RegistrationPacketSize;

        // Data packets: senderId!=0, receiverId!=0
        if (senderId != 0 && receiverId != 0)
        {
            // Negotiation packet (has magic bytes after header)
            if (size >= MinNegotiationPacketSize && HasMagicBytes(buffer))
                return true;

            // Game data packet (size > 8, no magic bytes)
            if (size > HeaderSize && !HasMagicBytes(buffer))
            {
                // Too small to be game data the client would have sent.
                if (size < MinGameDataPacketSize)
                    return false;

                return true;
            }

            // Has both IDs but doesn't match any known format
            return false;
        }

        // Doesn't match any valid format
        return false;
    }

    /// <summary>
    /// Whether a relay packet is a client-to-client negotiation packet within
    /// <paramref name="maxSize"/> bytes. Used by matchmaking servers, which relay the tunnel list
    /// exchange and nothing else - no game data, at any size.
    /// </summary>
    public static bool IsNegotiationPacket(ReadOnlySpan<byte> buffer, int maxSize)
        => buffer.Length >= MinNegotiationPacketSize && buffer.Length <= maxSize && HasMagicBytes(buffer);

    /// <summary>
    /// Checks if the buffer contains the magic bytes at the expected position.
    /// </summary>
    private static bool HasMagicBytes(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < HeaderSize + MagicBytes.Length)
            return false;

        return buffer.Slice(HeaderSize, MagicBytes.Length).SequenceEqual(MagicBytes);
    }
}
