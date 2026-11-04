using SslManager.Api.Models;

namespace SslManager.Api.Service;

/// <summary>接受 ACME DNS-01 挑战前，确认实际权威服务器已公开返回本轮精确 TXT 值。</summary>
public interface IAcmeDnsPropagationChecker
{
    Task<bool> IsVisibleAsync(IReadOnlyList<DnsChallenge> challenges, CancellationToken ct = default);
}
