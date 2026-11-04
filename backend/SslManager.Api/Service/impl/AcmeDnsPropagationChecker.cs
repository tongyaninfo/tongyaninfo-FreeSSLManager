using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>仅用公共 DoH 发现 NS，再向至少两个权威 NS 直接查询 TXT，拒绝仅本地解析缓存可见的验证值。</summary>
public sealed class AcmeDnsPropagationChecker(IHttpClientFactory clients) : IAcmeDnsPropagationChecker
{
    public async Task<bool> IsVisibleAsync(IReadOnlyList<DnsChallenge> challenges, CancellationToken ct = default)
    {
        if (challenges.Count == 0) return true;
        try
        {
            foreach (var challenge in challenges)
            {
                if (challenge.Type != "TXT" || !CloudJson.Domain(challenge.Domain) ||
                    !challenge.Name.TrimEnd('.').Equals("_acme-challenge." + challenge.Domain.TrimEnd('.'), StringComparison.OrdinalIgnoreCase) ||
                    challenge.Value.Length is 0 or > 512) return false;
                var names = await FindNameServersAsync(challenge.Name.TrimEnd('.'), ct);
                if (names.Count == 0) return false;
                var checkedNames = 0;
                foreach (var name in names.Take(2))
                {
                    var addresses = await Dns.GetHostAddressesAsync(name, AddressFamily.InterNetwork, ct);
                    var address = addresses.FirstOrDefault(IsPublic);
                    if (address is null || !await HasTxtAsync(address, challenge.Name, challenge.Value, ct)) return false;
                    checkedNames++;
                }
                if (checkedNames == 0) return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException or SocketException or JsonException or IOException or InvalidOperationException or KeyNotFoundException ||
                                   ex is OperationCanceledException && !ct.IsCancellationRequested)
        { return false; }
    }

    private async Task<IReadOnlyList<string>> FindNameServersAsync(string name, CancellationToken ct)
    {
        var current = name;
        for (var attempt = 0; attempt < 12 && current.Contains('.'); attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                "https://cloudflare-dns.com/dns-query?name=" + Uri.EscapeDataString(current) + "&type=NS");
            request.Headers.Accept.ParseAdd("application/dns-json");
            using var response = await clients.CreateClient("AcmeDns").SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode) return [];
            var limited = await CertificateDownloadHelper.ReadLimitedAsync(response.Content, 128 * 1024, ct);
            if (!limited.Success) return [];
            using var document = JsonDocument.Parse(limited.Data!);
            if (document.RootElement.TryGetProperty("Answer", out var answers) && answers.ValueKind == JsonValueKind.Array)
            {
                var result = answers.EnumerateArray().Where(x => x.TryGetProperty("type", out var type) && type.GetInt32() == 2)
                    .Select(x => x.GetProperty("data").GetString()?.TrimEnd('.') ?? "").Where(CloudJson.Domain).Distinct().ToArray();
                if (result.Length > 0) return result;
            }
            current = current[(current.IndexOf('.') + 1)..];
        }
        return [];
    }

    private static bool IsPublic(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address)) return false;
        var b = address.GetAddressBytes();
        return b[0] is not (0 or 10 or 127) && b[0] < 224 && !(b[0] == 169 && b[1] == 254) &&
            !(b[0] == 172 && b[1] is >= 16 and <= 31) && !(b[0] == 192 && b[1] == 168) && !(b[0] == 100 && b[1] is >= 64 and <= 127);
    }

    private static async Task<bool> HasTxtAsync(IPAddress address, string name, string expected, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(4));
        var packet = BuildQuery(name);
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(new IPEndPoint(address, 53));
        await udp.SendAsync(packet, timeout.Token);
        var response = await udp.ReceiveAsync(timeout.Token);
        return ContainsTxt(response.Buffer, packet, expected);
    }

    internal static byte[] BuildQuery(string name)
    {
        using var output = new MemoryStream();
        var header = new byte[12]; RandomNumberGenerator.Fill(header.AsSpan(0, 2));
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4, 2), 1); // RD=0，必须由权威直接回答。
        output.Write(header);
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63) throw new InvalidDataException("DNS label length");
            output.WriteByte((byte)bytes.Length); output.Write(bytes);
        }
        output.Write([0, 0, 16, 0, 1]);
        return output.ToArray();
    }

    internal static bool ContainsTxt(byte[] packet, byte[] query, string expected)
    {
        if (packet.Length < 12 || packet[0] != query[0] || packet[1] != query[1]) return false;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2));
        if ((flags & 0x8000) == 0 || (flags & 0x0400) == 0 || (flags & 0x020f) != 0) return false;
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2));
        var offset = 12;
        for (var i = 0; i < questionCount; i++) { if (!SkipName(packet, ref offset) || offset + 4 > packet.Length) return false; offset += 4; }
        for (var i = 0; i < answerCount; i++)
        {
            if (!SkipName(packet, ref offset) || offset + 10 > packet.Length) return false;
            var type = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));
            var cls = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 2, 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 8, 2)); offset += 10;
            if (offset + length > packet.Length) return false;
            if (type == 16 && cls == 1)
            {
                var end = offset + length; var text = new StringBuilder(); var cursor = offset;
                while (cursor < end)
                {
                    var partLength = packet[cursor++];
                    if (cursor + partLength > end) return false;
                    text.Append(Encoding.UTF8.GetString(packet, cursor, partLength)); cursor += partLength;
                }
                if (text.ToString().Equals(expected, StringComparison.Ordinal)) return true;
            }
            offset += length;
        }
        return false;
    }

    private static bool SkipName(byte[] packet, ref int offset)
    {
        for (var count = 0; count < 128 && offset < packet.Length; count++)
        {
            var size = packet[offset++];
            if (size == 0) return true;
            if ((size & 0xc0) == 0xc0) { if (offset >= packet.Length) return false; offset++; return true; }
            if (size > 63 || offset + size > packet.Length) return false;
            offset += size;
        }
        return false;
    }
}
