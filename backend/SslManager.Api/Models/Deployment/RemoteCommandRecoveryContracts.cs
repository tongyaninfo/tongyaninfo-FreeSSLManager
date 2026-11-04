namespace SslManager.Api.Models;

/// <summary>同一命令步骤跨重试共用远端锁；每次尝试拥有独立结果文件，历史现场不删除。</summary>
public sealed record RemoteCommandIdentity(string TaskId, string StepId, string CommandDigest, string Directory,
    bool Windows = false, int Attempt = 0);

/// <summary>Running 为仍持锁；Completed 为完整回执；StoppedUnknown 仅证明本尝试已结束但结果缺失。</summary>
public sealed record RemoteCommandEvidence(string State, int? ExitCode = null);
