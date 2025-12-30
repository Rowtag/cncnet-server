using System.Net;

namespace CnCNetServer.Security;

/// <summary>
/// Provides IP address anonymization for GDPR compliance.
/// Masks the last octet of IPv4 addresses and last 80 bits of IPv6 addresses.
/// </summary>
public static class IpAnonymizer
{
    /// <summary>
    /// Anonymizes an IP address by masking part of it.
    /// IPv4: Last octet set to 0 (e.g., 192.168.1.123 -> 192.168.1.0)
    /// IPv6: Last 80 bits set to 0
    /// </summary>
    public static string Anonymize(string? ipAddress)
    {
        if (string.IsNullOrEmpty(ipAddress))
            return "unknown";

        if (!IPAddress.TryParse(ipAddress, out var ip))
            return "invalid";

        return Anonymize(ip);
    }

    /// <summary>
    /// Anonymizes an IP address by masking part of it.
    /// </summary>
    public static string Anonymize(IPAddress? address)
    {
        if (address == null)
            return "unknown";

        var bytes = address.GetAddressBytes();

        if (bytes.Length == 4)
        {
            // IPv4: Mask last octet
            bytes[3] = 0;
        }
        else if (bytes.Length == 16)
        {
            // IPv6: Mask last 80 bits (bytes 6-15)
            for (var i = 6; i < 16; i++)
                bytes[i] = 0;
        }

        return new IPAddress(bytes).ToString();
    }
}
