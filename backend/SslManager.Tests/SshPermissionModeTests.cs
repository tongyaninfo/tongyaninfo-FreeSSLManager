using System.Runtime.CompilerServices;
using Renci.SshNet.Sftp;
using SslManager.Api.Service.impl.Deployment.Transports;

namespace SslManager.Tests;

/// <summary>针对 SSH.NET 实际权限解析器回归，避免暂存私钥因 384/600 表示差异在 chmod 时失败。</summary>
public sealed class SshPermissionModeTests
{
    [Theory]
    [InlineData(0, 0)]
    [InlineData(384, 600)]
    [InlineData(416, 640)]
    [InlineData(420, 644)]
    [InlineData(448, 700)]
    [InlineData(493, 755)]
    [InlineData(511, 777)]
    [InlineData(1023, 1777)]
    [InlineData(2541, 4755)]
    [InlineData(4095, 7777)]
    public void ConvertedModeIsAcceptedBySshNetAndPreservesPermissionBits(short bits, short expectedMode)
    {
        var mode = SshRemoteTransport.ToSftpPermissionMode(bits);
        Assert.Equal(expectedMode, mode);
        var attributes = EmptyAttributes();
        attributes.SetPermissions(mode);

        Assert.Equal((bits & 256) != 0, attributes.OwnerCanRead);
        Assert.Equal((bits & 128) != 0, attributes.OwnerCanWrite);
        Assert.Equal((bits & 64) != 0, attributes.OwnerCanExecute);
        Assert.Equal((bits & 32) != 0, attributes.GroupCanRead);
        Assert.Equal((bits & 16) != 0, attributes.GroupCanWrite);
        Assert.Equal((bits & 8) != 0, attributes.GroupCanExecute);
        Assert.Equal((bits & 4) != 0, attributes.OthersCanRead);
        Assert.Equal((bits & 2) != 0, attributes.OthersCanWrite);
        Assert.Equal((bits & 1) != 0, attributes.OthersCanExecute);
        Assert.Equal((bits & 512) != 0, attributes.IsStickyBitSet);
        Assert.Equal((bits & 1024) != 0, attributes.IsGroupIDBitSet);
        Assert.Equal((bits & 2048) != 0, attributes.IsUIDBitSet);
    }

    [Fact]
    public void SshNetRejectsTheUnconvertedPrivateKeyPermissionMask()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => EmptyAttributes().SetPermissions(384));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(4096)]
    [InlineData(short.MaxValue)]
    public void InvalidPermissionBitsAreRejectedBeforeRemoteCreation(short bits)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SshRemoteTransport.ToSftpPermissionMode(bits));
    }

    private static SftpFileAttributes EmptyAttributes() =>
        // 该类型只通过内部 SFTP 报文构造；测试仅调用纯权限解析，无需连接服务器或伪造报文。
        (SftpFileAttributes)RuntimeHelpers.GetUninitializedObject(typeof(SftpFileAttributes));
}
