using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service.impl;
using Xunit;

namespace SslManager.Tests;

/// <summary>云适配均使用本地 HTTP 替身，验证分页、免费边界、DNS 精确删除及密钥输出约束。</summary>
public sealed class CloudProviderTests
{
    [Fact]
    public async Task TencentReadsEveryPageAndDoesNotInferFreeFromIssuer()
    {
        var factory = new FakeFactory(r =>
        {
            var offset = r.Json.GetProperty("Offset").GetInt32();
            var statuses = r.Json.GetProperty("CertificateStatus").EnumerateArray().Select(x => x.GetInt32()).ToArray();
            if (statuses.Length != 16)
                return Json(new { Response = new { TotalCount = 0, Certificates = Array.Empty<object>(), RequestId = "historical-empty" } });
            var rows = Enumerable.Range(offset, offset == 0 ? 100 : 1).Select(n => new
            { CertificateId = "cert" + n, Domain = "example.com", PackageType = n == 0 ? "" : "83", From = "trustasia", Status = n == 0 ? 999 : 1 });
            return Json(new { Response = new { TotalCount = 101, Certificates = rows, RequestId = "page-" + offset } });
        });
        var r = await Tencent(factory).ListAsync(Account());
        Assert.True(r.Success);
        Assert.Equal(101, r.Data!.Count);
        Assert.Null(r.Data[0].IsFree);
        Assert.Equal("Unknown", r.Data[0].Status);
        Assert.True(r.Data[100].IsFree);
        Assert.Equal("page-100", r.Data[100].RequestId);
        Assert.Equal(3, factory.Requests.Count);
    }

    [Fact]
    public async Task TencentCertificateListRequestsAllKnownStatusesIncludingExpiredAndRevoked()
    {
        var factory = new FakeFactory(r =>
        {
            var statuses = r.Json.GetProperty("CertificateStatus").EnumerateArray().Select(x => x.GetInt32()).ToArray();
            Assert.Equal(Enumerable.Range(0, 16), statuses);
            return Json(new { Response = new
            {
                TotalCount = 2,
                Certificates = new[]
                {
                    new { CertificateId = "expired", Domain = "expired.example.com", PackageType = "83", Status = 3 },
                    new { CertificateId = "revoked", Domain = "revoked.example.com", PackageType = "83", Status = 10 }
                },
                RequestId = "historical"
            } });
        });

        var result = await Tencent(factory).ListAsync(Account());

        Assert.True(result.Success);
        Assert.Equal(new[] { "Expired", "Revoked" }, result.Data!.Select(x => x.Status));
        Assert.Single(factory.Requests);
    }

    [Fact]
    public async Task TencentCertificateListRecoversHistoricalStatusesWhenPrimarySnapshotOmitsThem()
    {
        var factory = new FakeFactory(r =>
        {
            var statuses = r.Json.GetProperty("CertificateStatus").EnumerateArray().Select(x => x.GetInt32()).ToArray();
            if (statuses.Contains(3) && statuses.Contains(10) && statuses.Length == 16)
            {
                return Json(new { Response = new
                {
                    TotalCount = 1,
                    Certificates = new[] { new { CertificateId = "issued", Domain = "issued.example.com", PackageType = "83", Status = 1 } },
                    RequestId = "primary"
                } });
            }

            Assert.Contains(3, statuses);
            Assert.Contains(10, statuses);
            return Json(new { Response = new
            {
                TotalCount = 2,
                Certificates = new[]
                {
                    new { CertificateId = "expired", Domain = "expired.example.com", PackageType = "83", Status = 3 },
                    new { CertificateId = "revoked", Domain = "revoked.example.com", PackageType = "83", Status = 10 }
                },
                RequestId = "historical"
            } });
        });

        var result = await Tencent(factory).ListAsync(Account());

        Assert.True(result.Success);
        Assert.Equal(new[] { "issued", "expired", "revoked" }, result.Data!.Select(x => x.Reference.CertificateId));
        Assert.Equal(2, factory.Requests.Count);
    }

    [Fact]
    public async Task TencentRejectsDuplicateOrChangingPagesInsteadOfReturningPartialList()
    {
        var factory = new FakeFactory(r => Json(new { Response = new { TotalCount = 2,
            Certificates = new[] { new { CertificateId = "same", PackageType = "83", Status = 1 } }, RequestId = "id" } }));
        var result = await Tencent(factory).ListAsync(Account());
        Assert.False(result.Success);
        Assert.Equal("CloudPaginationIncomplete", result.Code);
        Assert.Null(result.Data);
    }

    [Fact]
    public async Task TencentRetriesFromFirstPageWhenRecordCountChangesAndReturnsCompleteSnapshot()
    {
        var calls = 0;
        var factory = new FakeFactory(_ =>
        {
            calls++;
            // 第一轮翻页时总数发生变化；第二轮从第一页重新读取后返回完整列表。
            if (calls == 1)
                return Json(new { Response = new { RecordCountInfo = new { TotalCount = 2, ListCount = 1 },
                    RecordList = new[] { new { RecordId = 1, Name = "a", Type = "A", Value = "192.0.2.1", TTL = 600, Status = "ENABLE" } }, RequestId = "first" } });
            if (calls == 2)
                return Json(new { Response = new { RecordCountInfo = new { TotalCount = 3, ListCount = 1 },
                    RecordList = new[] { new { RecordId = 2, Name = "b", Type = "A", Value = "192.0.2.2", TTL = 600, Status = "ENABLE" } }, RequestId = "changed" } });
            return Json(new { Response = new { RecordCountInfo = new { TotalCount = 2, ListCount = 2 },
                RecordList = new[] {
                    new { RecordId = 1, Name = "a", Type = "A", Value = "192.0.2.1", TTL = 600, Status = "ENABLE" },
                    new { RecordId = 2, Name = "b", Type = "A", Value = "192.0.2.2", TTL = 600, Status = "ENABLE" },
                }, RequestId = "stable" } });
        });

        var result = await Tencent(factory).ListRecordsAsync(Account(), "example.com");

        Assert.True(result.Success);
        Assert.Equal(2, result.Data!.Count);
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task TencentDnsListsRequestSingleFullPageToAvoidUnstableSnapshots()
    {
        var factory = new FakeFactory(r => r.Action switch
        {
            "DescribeDomainList" => Json(new { Response = new
            {
                DomainCountInfo = new { DomainTotal = 1 },
                DomainList = new[] { new { DomainId = 1001, Name = "example.com", Status = "ENABLE" } },
                RequestId = "domains"
            } }),
            "DescribeRecordList" => Json(new { Response = new
            {
                RecordCountInfo = new { TotalCount = 1, ListCount = 1 },
                RecordList = new[] { new { RecordId = 88, Name = "@", Type = "A", Value = "192.0.2.1", TTL = 600, Status = "ENABLE" } },
                RequestId = "records"
            } }),
            _ => Json(new { Response = new { RequestId = "unexpected" } })
        });

        var zones = await Tencent(factory).ListZonesAsync(Account());
        var records = await Tencent(factory).ListRecordsAsync(Account(), "example.com");

        Assert.True(zones.Success);
        Assert.True(records.Success);
        Assert.Equal("1001", zones.Data![0].Id);
        Assert.Equal("88", records.Data![0].Id);
        Assert.All(factory.Requests.Where(x => x.Action is "DescribeDomainList" or "DescribeRecordList"),
            request => Assert.Equal(3000, request.Json.GetProperty("Limit").GetInt32()));
    }

    [Fact]
    public async Task TencentAcceptsStableRecordSnapshotWhenDeletionLeavesStaleTotalCount()
    {
        var factory = new FakeFactory(request => request.Json.GetProperty("Offset").GetInt32() == 0
            ? Json(new { Response = new
            {
                // 模拟删除后云端列表已经只有两条，但 TotalCount 仍暂时保留删除前的三条。
                RecordCountInfo = new { TotalCount = 3, ListCount = 2 },
                RecordList = new[]
                {
                    new { RecordId = 1, Name = "a", Type = "TXT", Value = "one", TTL = 600, Status = "ENABLE" },
                    new { RecordId = 2, Name = "b", Type = "TXT", Value = "two", TTL = 600, Status = "ENABLE" },
                },
                RequestId = "stale-count"
            }})
            : Json(new { Response = new
            {
                RecordCountInfo = new { TotalCount = 3, ListCount = 0 },
                RecordList = Array.Empty<object>(),
                RequestId = "stale-count-end"
            }}));

        var result = await Tencent(factory).ListRecordsAsync(Account(), "example.com");

        Assert.True(result.Success);
        Assert.Equal(new[] { "1", "2" }, result.Data!.Select(x => x.Id));
        // 每轮会继续探测下一页，连续两次集合一致后才接受，不能把旧 TotalCount 当成部分结果错误返回。
        Assert.Equal(4, factory.Requests.Count);
    }

    [Fact]
    public async Task TencentAcceptsEmptyRecordArrayWhenCountMetadataIsTemporarilyMissing()
    {
        var factory = new FakeFactory(_ => Json(new { Response = new
        {
            RecordList = Array.Empty<object>(),
            RequestId = "empty"
        }}));

        var result = await Tencent(factory).ListRecordsAsync(Account(), "example.com");

        Assert.True(result.Success);
        Assert.Empty(result.Data!);
        Assert.Equal(2, factory.Requests.Count);
    }

    [Fact]
    public async Task TencentCreateWaitsForEventuallyConsistentRecordIndexBeforeReturning()
    {
        var listCalls = 0;
        var factory = new FakeFactory(request =>
        {
            if (request.Action == "CreateRecord")
                return Json(new { Response = new { RecordId = 99, RequestId = "created" } });

            listCalls++;
            if (listCalls <= 2)
            {
                // 写入响应已经返回，但第一页仍是旧索引；第二页为空且计数仍是旧值。
                return Json(new { Response = new
                {
                    RecordCountInfo = new { TotalCount = 2, ListCount = listCalls == 1 ? 1 : 0 },
                    RecordList = listCalls == 1
                        ? new[] { new { RecordId = 1, Name = "old", Type = "TXT", Value = "one", TTL = 600, Status = "ENABLE" } }
                        : Array.Empty<object>(),
                    RequestId = "stale-" + listCalls
                }});
            }

            return Json(new { Response = new
            {
                RecordCountInfo = new { TotalCount = 2, ListCount = 2 },
                RecordList = new[]
                {
                    new { RecordId = 1, Name = "old", Type = "TXT", Value = "one", TTL = 600, Status = "ENABLE" },
                    new { RecordId = 99, Name = "aaa", Type = "TXT", Value = "two", TTL = 600, Status = "ENABLE" }
                },
                RequestId = "stable"
            }});
        });

        var result = await Tencent(factory).CreateRecordAsync(Account(), "example.com", new("aaa", "TXT", "two"));

        Assert.True(result.Success);
        Assert.Equal("99", result.Data!.Id);
        Assert.Equal(3, listCalls);
        Assert.Contains(factory.Requests, x => x.Action == "CreateRecord");
    }

    [Theory]
    [InlineData("NativeAutoDns", true, "DNS_AUTO")]
    [InlineData("NativeAutoDns", false, "DNS_AUTO")]
    [InlineData("ManagedDns", true, "DNS")]
    public async Task TencentApplicationOnlyUsesFreeProductAndNativeCleanupFlag(string mode, bool cleanup, string expectedMode)
    {
        var factory = new FakeFactory(r => r.Action == "ApplyCertificate"
            ? Json(new { Response = new { CertificateId = "cert1", RequestId = "apply-id" } })
            : Json(new { Response = new { CertificateId = "cert1", Domain = "example.com", PackageType = "83", Status = 0, RequestId = "get-id" } }));
        var result = await Tencent(factory).ApplyAsync(Account(), new("example.com", mode, cleanup, Alias: "测试"));
        Assert.True(result.Success);
        var input = factory.Requests.Single(x => x.Action == "ApplyCertificate").Json;
        Assert.Equal("83", input.GetProperty("PackageType").GetString());
        Assert.Equal(expectedMode, input.GetProperty("DvAuthMethod").GetString());
        Assert.Equal("测试", input.GetProperty("Alias").GetString());
        if (mode == "NativeAutoDns") Assert.Equal(cleanup, input.GetProperty("DeleteDnsAutoRecord").GetBoolean());
        else Assert.False(input.TryGetProperty("DeleteDnsAutoRecord", out _));
    }

    [Fact]
    public async Task SubmittedTencentApplicationRetainsCloudIdWhenFollowupQueryFails()
    {
        var factory = new FakeFactory(r => r.Action == "ApplyCertificate"
            ? Json(new { Response = new { CertificateId = "submitted", RequestId = "submit-id" } })
            : throw new HttpRequestException("simulated infrastructure failure"));
        var result = await Tencent(factory).ApplyAsync(Account(), new("example.com"));
        Assert.True(result.Success);
        Assert.Equal("submitted", result.Data!.Certificate.Reference.CertificateId);
        Assert.Equal("Pending", result.Data.Certificate.Status);
    }

    [Fact]
    public async Task TencentDetailSeparatesRevocationChallengesAndUsesFullRecordName()
    {
        var factory = new FakeFactory(_ => Json(new { Response = new
        {
            CertificateId = "cert1", Domain = "vpn.example.com", PackageType = "83", Status = 9,
            DvAuthDetail = new { DvAuths = new[] { new
            {
                DvAuthDomain = "vpn.example.com", DvAuthKey = "_apply.vpn.example.com",
                DvAuthValue = "apply-proof", DvAuthVerifyType = "TXT"
            } } },
            DvRevokeAuthDetail = new[] { new
            {
                DvAuthDomain = "vpn.example.com", DvAuthKey = "_revoke.vpn.example.com",
                DvAuthSubDomain = "_revoke", DvAuthValue = "revoke-proof.example.net", DvAuthVerifyType = "cname"
            } },
            RequestId = "detail"
        } }));

        var result = await Tencent(factory).GetAsync(Account(), new("cert1"));

        Assert.True(result.Success);
        Assert.Equal("Revoking", result.Data!.Certificate.Status);
        Assert.Equal("_apply.vpn.example.com", Assert.Single(result.Data.Challenges).Name);
        var revocation = Assert.Single(result.Data.RevocationChallenges!);
        Assert.Equal("_revoke.vpn.example.com", revocation.Name);
        Assert.Equal("CNAME", revocation.Type);
        Assert.Equal("revoke-proof.example.net", revocation.Value);
        Assert.False(revocation.IsRelative);
        Assert.Single(factory.Requests);
    }

    [Theory]
    [InlineData("FILE", "FILE")]
    [InlineData(null, "")]
    public async Task TencentRevocationDetailDoesNotInferDnsType(string? cloudType, string expectedType)
    {
        var factory = new FakeFactory(_ => Json(new { Response = new
        {
            CertificateId = "cert1", Domain = "example.com", PackageType = "83", Status = 9,
            DvRevokeAuthDetail = new[] { new
            {
                DvAuthDomain = "example.com", DvAuthKey = "fileauth.txt", DvAuthValue = "proof",
                DvAuthPath = "/.well-known/pki-validation/", DvAuthVerifyType = cloudType
            } },
            RequestId = "detail"
        } }));

        var result = await Tencent(factory).GetAsync(Account(), new("cert1"));

        Assert.True(result.Success);
        Assert.Empty(result.Data!.Challenges);
        Assert.Equal(expectedType, Assert.Single(result.Data.RevocationChallenges!).Type);
    }

    [Fact]
    public async Task TencentRevokeResponseWithoutTypeDoesNotInventDnsChallengeOrAutomaticFlag()
    {
        var factory = new FakeFactory(r => r.Action == "DescribeCertificate"
            ? Json(new { Response = new { CertificateId = "cert1", Domain = "example.com", PackageType = "83", Status = 1, RequestId = "detail" } })
            : Json(new { Response = new
            {
                RevokeDomainValidateAuths = new[] { new
                {
                    DomainValidateAuthDomain = "example.com", DomainValidateAuthKey = "fileauth.txt",
                    DomainValidateAuthPath = "/.well-known/pki-validation/", DomainValidateAuthValue = "proof"
                } },
                RequestId = "revoke"
            } }));

        var result = await Tencent(factory).RevokeAsync(Account(), new("cert1"), "renewed");

        Assert.True(result.Success);
        Assert.Equal("", Assert.Single(result.Data!.Challenges!).Type);
        var input = factory.Requests.Single(x => x.Action == "RevokeCertificate").Json;
        Assert.Equal(new[] { "CertificateId", "Reason" }, input.EnumerateObject().Select(x => x.Name).Order());
    }

    [Fact]
    public async Task CloudBusinessErrorIsResultAndNeverCopiesRemoteSecretMessage()
    {
        var factory = new FakeFactory(_ => Json(new { Response = new { Error = new { Code = "AuthFailure", Message = "remote-secret-material" }, RequestId = "request-123" } }));
        var result = await Tencent(factory).TestAsync(Account());
        Assert.Equal("Tencent.AuthFailure", result.Code);
        Assert.Contains("request-123", result.Message);
        Assert.DoesNotContain("remote-secret-material", JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task NetworkFailureDuringMutationIsUnknownAndHasNoAutomaticRetry()
    {
        var factory = new FakeFactory(_ => throw new HttpRequestException("network unavailable"));
        var result = await Tencent(factory).ApplyAsync(Account(), new("example.com"));
        Assert.Equal("OutcomeUnknown", result.Code);
        Assert.Single(factory.Requests);
    }

    [Fact]
    public async Task AliyunRejectsLegacyV1ApplyInsteadOfCreatingAnOldOrder()
    {
        var factory = new FakeFactory(r => r.Action switch
        {
            "CreateCertificateRequest" => Json(new { OrderId = 9, RequestId = "create" }),
            "ListUserCertificateOrder" => Json(new { TotalCount = 1, CertificateOrderList = new[] { new { OrderId = 9, ProductCode = "digicert-free-1-free", Domain = "www.example.com", Status = "CHECKING" } }, RequestId = "list" }),
            _ => Json(new { Type = "domain_verify", ValidateType = "DNS", RecordDomain = "_dnsauth.www", RecordType = "TXT", RecordValue = "proof", PrivateKey = "private-material-must-never-appear", RequestId = "state" })
        });
        var result = await Aliyun(factory).ApplyAsync(Account("Aliyun"), new("www.example.com", "ManagedDns", Alias: "免费证书", ApiVersion: "V1"));
        Assert.False(result.Success);
        Assert.Equal("InvalidInput", result.Code);
        Assert.Empty(factory.Requests);
    }

    [Theory]
    [InlineData("symantec-free-1-free")]
    [InlineData("unknown-test-spec")]
    public async Task AliyunV2NeverAppliesUnconfirmedFreeOrProInstance(string spec)
    {
        var factory = new FakeFactory(_ => Json(new { InstanceId = "cas-test", InstanceType = "TEST", Spec = spec, RequestId = "read" }));
        var result = await Aliyun(factory).ApplyAsync(Account("Aliyun"), new("example.com", InstanceId: "cas-test", ApiVersion: "V2"));
        Assert.Equal("FREE_PRODUCT_UNCONFIRMED", result.Code);
        Assert.Single(factory.Requests);
        Assert.Equal("GetInstanceDetail", factory.Requests[0].Action);
    }

    [Fact]
    public async Task AliyunV2AcceptsBasicFreeTestInstanceSpec()
    {
        var applied = false;
        var factory = new FakeFactory(input =>
        {
            if (input.Action == "ApplyCertificate") applied = true;
            return Json(new
            {
                InstanceId = "cas-test", InstanceType = "TEST", Spec = "ss.dv.t", Status = "inactive",
                RequestId = "read", Domain = applied ? "example.com" : "", CertificateName = "test", ContactIdList = new[] { 123 }
            });
        });

        var result = await Aliyun(factory).ApplyAsync(Account("Aliyun"), new("example.com", InstanceId: "cas-test", ApiVersion: "V2"));

        Assert.True(result.Success);
        Assert.Equal("ss.dv.t", result.Data!.Certificate.ProductCode);
        Assert.Contains(factory.Requests, x => x.Action == "ApplyCertificate");
        Assert.Equal("123", factory.Requests.Single(x => x.Action == "UpdateInstance").Fields["ContactIdList.1"]);
    }

    [Theory]
    [InlineData("issued-certificate", "", "inactive")]
    [InlineData("", "another.example.com", "inactive")]
    [InlineData("", "occupied-value", "inactive")]
    [InlineData("", "one.example.com,two.example.com", "inactive")]
    [InlineData("", "", "issued")]
    [InlineData("", "", "pending")]
    public async Task AliyunRechecksFreeInstanceOccupancyImmediatelyBeforeApplying(string certificateId, string domain, string status)
    {
        var factory = new FakeFactory(input => input.Action == "ListInstances"
            ? Json(new
            {
                TotalCount = 1, InstanceList = new[] { new
                {
                    InstanceId = "cas-test", InstanceType = "TEST", Spec = "ss.dv.t", Status = "inactive", CertificateId = "", Domain = ""
                } }, RequestId = "list"
            })
            : Json(new
            {
                InstanceId = "cas-test", InstanceType = "TEST", Spec = "ss.dv.t", Status = status,
                CertificateId = certificateId, Domain = domain, ContactIdList = new[] { 123 }, RequestId = "read"
            }));
        var service = Aliyun(factory);
        Assert.Single((await service.ListAliyunInstancesAsync(Account("Aliyun"))).Data!);

        var result = await service.ApplyAsync(Account("Aliyun"), new("example.com", InstanceId: "cas-test", ApiVersion: "V2"));

        Assert.False(result.Success);
        Assert.Equal("TEST_INSTANCE_ALREADY_USED", result.Code);
        Assert.Equal(new[] { "ListInstances", "GetInstanceDetail" }, factory.Requests.Select(request => request.Action));
        Assert.DoesNotContain(factory.Requests, request => request.Action is "UpdateInstance" or "ApplyCertificate");
    }

    [Fact]
    public async Task AliyunV2MissingContactReturnsBusinessErrorBeforeApplying()
    {
        var factory = new FakeFactory(r => r.Action == "ListContact"
            ? Json(new { TotalCount = 0, ContactList = Array.Empty<object>(), RequestId = "contacts" })
            : Json(new { InstanceId = "cas-test", InstanceType = "TEST", Spec = "ss.dv.t", Status = "inactive", RequestId = "read" }));

        var result = await Aliyun(factory).ApplyAsync(Account("Aliyun"), new("example.com", InstanceId: "cas-test", ApiVersion: "V2"));

        Assert.False(result.Success);
        Assert.Equal("ALIYUN_CONTACT_REQUIRED", result.Code);
        Assert.DoesNotContain(factory.Requests, x => x.Action is "UpdateInstance" or "ApplyCertificate");
    }

    [Fact]
    public async Task AliyunListsVerifiedContactFieldsWithoutReturningWebhookData()
    {
        var factory = new FakeFactory(_ => Json(new
        {
            TotalCount = 2,
            ContactList = new[]
            {
                new { ContactId = 123, Name = "张三", Mobile = "13900000000", MobileStatus = 1, Email = "zhang@example.com", EmailStatus = 1, Webhooks = "secret-webhook" },
                new { ContactId = 456, Name = "李四", Mobile = "13800000000", MobileStatus = 0, Email = "li@example.com", EmailStatus = 1, Webhooks = "" }
            },
            RequestId = "contacts"
        }));

        var result = await Aliyun(factory).ListContactsAsync(Account("Aliyun"));

        Assert.True(result.Success);
        Assert.Equal(2, result.Data!.Count);
        Assert.Equal("123", result.Data[0].Id);
        Assert.True(result.Data[0].MobileVerified);
        Assert.False(result.Data[1].MobileVerified);
        Assert.DoesNotContain("secret-webhook", JsonSerializer.Serialize(result));
        Assert.Equal("ListContact", factory.Requests.Single().Action);
    }

    [Fact]
    public async Task AliyunListsOnlyUnusedBasicFreeV2InstancesForApplySelection()
    {
        var factory = new FakeFactory(_ => Json(new
        {
            TotalCount = 3,
            InstanceList = new[]
            {
                new { InstanceId = "free-unused", InstanceType = "TEST", Spec = "ss.dv.t", Status = "inactive", CertificateId = "", Domain = "" },
                new { InstanceId = "free-used", InstanceType = "TEST", Spec = "ss.dv.t", Status = "issued", CertificateId = "77", Domain = "example.com" },
                new { InstanceId = "pro-unused", InstanceType = "TEST", Spec = "pro", Status = "inactive", CertificateId = "", Domain = "" }
            },
            RequestId = "instances"
        }));

        var result = await Aliyun(factory).ListAliyunInstancesAsync(Account("Aliyun"));

        Assert.True(result.Success);
        var item = Assert.Single(result.Data!);
        Assert.Equal("free-unused", item.InstanceId);
        Assert.Equal("ss.dv.t", item.Spec);
        Assert.Equal("ListInstances", factory.Requests.Single().Action);
    }

    [Fact]
    public async Task AliyunV2UsesCloudRemarkAndPrimaryDomainWhenCloudAddsWwwAlias()
    {
        var factory = new FakeFactory(r => r.Action switch
        {
            "GetInstanceDetail" => Json(new
            {
                InstanceId = "cas-test", InstanceType = "TEST", Spec = "ss.dv.t", Status = "inactive",
                CertificateId = 123, Domain = "example.com\nwww.example.com", CertificateName = "cert-hdm4n", RequestId = "detail"
            }),
            _ => Json(new { RequestId = "follow-up" })
        });

        var result = await Aliyun(factory).GetAsync(Account("Aliyun"), new(InstanceId: "cas-test", ApiVersion: "V2"));

        Assert.True(result.Success);
        Assert.Equal("example.com", result.Data!.Certificate.Domain);
        Assert.Equal("cert-hdm4n", result.Data.Certificate.Alias);
    }

    [Fact]
    public async Task AliyunV2UsesSavedContactIdWithoutMatchingByManualContactFields()
    {
        var factory = new FakeFactory(r => r.Action switch
        {
            "GetInstanceDetail" => Json(new { InstanceId = "cas-test", InstanceType = "TEST", Spec = "ss.dv.t", Status = "inactive", ContactIdList = new[] { 123 }, RequestId = "read" }),
            "UpdateInstance" => Json(new { RequestId = "update" }),
            "ApplyCertificate" => Json(new { RequestId = "apply" }),
            _ => Json(new { RequestId = "follow-up" })
        });

        var result = await Aliyun(factory).ApplyAsync(Account("Aliyun", "987654"),
            new("example.com", InstanceId: "cas-test", ApiVersion: "V2"));

        Assert.True(result.Success);
        Assert.Equal("987654", factory.Requests.Single(x => x.Action == "UpdateInstance").Fields["ContactIdList.1"]);
        Assert.DoesNotContain(factory.Requests, x => x.Action == "ListContact");
    }

    [Fact]
    public async Task AliyunV2HistoricalCertificateMustBelongToRequestedInstance()
    {
        var factory = new FakeFactory(r => r.Action == "GetInstanceDetail"
            ? Json(new { InstanceId = "instance1", CertificateId = 20, InstanceType = "TEST", Spec = "digicert-free-1-free", RequestId = "instance" })
            : Json(new { InstanceId = "different", CertificateId = 10, CertificateStatus = "issued", RequestId = "certificate" }));
        var result = await Aliyun(factory).GetAsync(Account("Aliyun"), new("10", InstanceId: "instance1", ApiVersion: "V2"));
        Assert.False(result.Success);
        Assert.Equal("CloudIdentityMismatch", result.Code);
        Assert.Equal(2, factory.Requests.Count);
    }

    [Fact]
    public async Task AliyunV2DoesNotReturnDeletedCertificateFromClosedInstanceMetadata()
    {
        // 云端删除证书后，已关闭实例仍可能保留原证书 ID 和已吊销状态。
        var factory = new FakeFactory(input => input.Action switch
        {
            "GetInstanceDetail" => Json(new { InstanceId = "instance1", CertificateId = 123, InstanceType = "TEST",
                Spec = "ss.dv.t", Status = "closed", CertificateStatus = "revoked", RequestId = "stale-instance" }),
            "GetCertificateDetail" => Json(new { Code = "NotFound", RequestId = "missing-certificate" }),
            _ => throw new InvalidOperationException("详情核验不应执行其他云操作。")
        });

        var result = await Aliyun(factory).GetAsync(Account("Aliyun"), new("123", InstanceId: "instance1", ApiVersion: "V2"));

        Assert.False(result.Success);
        Assert.Equal("Aliyun.NotFound", result.Code);
        Assert.Equal("123", factory.Requests.Single(x => x.Action == "GetCertificateDetail").Fields["CertificateId"]);
    }

    [Fact]
    public async Task AliyunV2CurrentCertificateMustBelongToRequestedInstance()
    {
        var factory = new FakeFactory(input => input.Action switch
        {
            "GetInstanceDetail" => Json(new { InstanceId = "instance1", CertificateId = 123, InstanceType = "TEST",
                Spec = "ss.dv.t", CertificateStatus = "revoked", RequestId = "instance" }),
            "GetCertificateDetail" => Json(new { InstanceId = "different-instance", CertificateId = 123,
                CertificateStatus = "revoked", RequestId = "certificate" }),
            _ => throw new InvalidOperationException("详情核验不应执行其他云操作。")
        });

        var result = await Aliyun(factory).GetAsync(Account("Aliyun"), new("123", InstanceId: "instance1", ApiVersion: "V2"));

        Assert.False(result.Success);
        Assert.Equal("CloudIdentityMismatch", result.Code);
    }

    [Fact]
    public async Task AliyunV2CurrentCertificateSurvivesExactExistenceCheck()
    {
        var factory = new FakeFactory(input => input.Action switch
        {
            "GetInstanceDetail" => Json(new { InstanceId = "instance1", CertificateId = 123, InstanceType = "TEST",
                Spec = "ss.dv.t", Status = "closed", CertificateStatus = "revoked", Domain = "example.com",
                DomainValidationList = new[] { new { Domain = "example.com", RootDomain = "example.com",
                    ValidationKey = "_dnsauth", ValidationType = "TXT", ValidationValue = "validation-proof" } }, RequestId = "instance" }),
            "GetCertificateDetail" => Json(new { InstanceId = "instance1", CertificateId = 123,
                CertificateStatus = "revoked", Domain = "example.com", RequestId = "certificate" }),
            _ => throw new InvalidOperationException("详情核验不应执行其他云操作。")
        });

        var result = await Aliyun(factory).GetAsync(Account("Aliyun"), new("123", InstanceId: "instance1", ApiVersion: "V2"));

        Assert.True(result.Success);
        Assert.Equal("123", result.Data!.Certificate.Reference.CertificateId);
        Assert.Equal("instance1", result.Data.Certificate.Reference.InstanceId);
        Assert.Equal("Revoked", result.Data.Certificate.Status);
        Assert.True(result.Data.Certificate.IsFree);
        var challenge = Assert.Single(result.Data.Challenges);
        Assert.Equal("_dnsauth.example.com", challenge.Name);
        Assert.Equal("validation-proof", challenge.Value);
        Assert.Contains(factory.Requests, input => input.Action == "GetCertificateDetail");
    }

    [Fact]
    public async Task AliyunV2CancellationUsesPendingCertificateApi()
    {
        var factory = new FakeFactory(_ => Json(new { RequestId = "cancel-v2" }));

        var result = await Aliyun(factory).CancelAsync(Account("Aliyun"), new(InstanceId: "cas-test", ApiVersion: "V2"));

        Assert.True(result.Success);
        Assert.Equal("Cancelled", result.Data!.State);
        Assert.Equal("CancelPendingCertificate", factory.Requests.Single().Action);
        Assert.Equal("cas-test", factory.Requests.Single().Fields["InstanceId"]);
    }

    [Fact]
    public async Task AliyunV2CancelledInstanceUsesInstanceDeletionWhenNoCertificateExists()
    {
        var factory = new FakeFactory(_ => Json(new { RequestId = "delete-v2" }));

        var result = await Aliyun(factory).DeleteAsync(Account("Aliyun"), new(InstanceId: "cas-test", ApiVersion: "V2"));

        Assert.True(result.Success);
        Assert.Equal("DeleteInstance", factory.Requests.Single().Action);
        Assert.Equal("cas-test", factory.Requests.Single().Fields["InstanceId"]);
    }

    [Fact]
    public async Task AliyunPersistentAuthorizationWinsWhenRecordAlsoAppearsAsTemporaryChallenge()
    {
        var factory = new FakeFactory(_ => Json(new { InstanceId = "instance1", InstanceType = "TEST", Spec = "ss.dv.t", Status = "pending",
            DomainValidationList = new[] { new { Domain = "example.com", RootDomain = "example.com", ValidationKey = "_dnsauth", ValidationType = "CNAME",
                ValidationValue = "proof.example.net", CnameKey = "_dnsauth", Cname = "proof.example.net" } }, RequestId = "instance" }));
        var result = await Aliyun(factory).GetAsync(Account("Aliyun"), new(InstanceId: "instance1", ApiVersion: "V2"));
        Assert.True(result.Success);
        Assert.Single(result.Data!.Challenges);
        Assert.True(result.Data.Challenges[0].IsPersistent);
    }

    [Fact]
    public async Task MalformedCloudRowsAreBusinessFailuresAndInvalidDnsInputDoesNotSendRequests()
    {
        var factory = new FakeFactory(_ => Json(new { Response = new { TotalCount = 1, Certificates = new[] { "malformed" }, RequestId = "page" } }));
        var malformed = await Tencent(factory).ListAsync(Account());
        Assert.Equal("CloudPaginationIncomplete", malformed.Code);
        var invalid = await Tencent(factory).CreateRecordAsync(Account(), "example.com", new(null!, "TXT", "value"));
        Assert.Equal("InvalidInput", invalid.Code);
        Assert.Single(factory.Requests);
    }

    [Fact]
    public async Task AliyunListsOldOrdersAndNewInstancesWithoutDoubleCountingLatestCertificate()
    {
        var factory = new FakeFactory(r => r.Action switch
        {
            "ListUserCertificateOrder" => Json(new { TotalCount = 1, CertificateOrderList = new[] { new { OrderId = 5, CertificateId = 55, ProductCode = "digicert-free-1-free", Status = "ISSUED", Domain = "old.example.com" } }, RequestId = "old" }),
            "ListInstances" => Json(new { TotalCount = 1, InstanceList = new[] { new { InstanceId = "instance1", CertificateId = 77, InstanceType = "TEST", Spec = "ss.dv.t", Domain = "new.example.com", CertificateStatus = "issued" } }, RequestId = "instances" }),
            _ => Json(new { TotalCount = 1, CertificateList = new[] { new { InstanceId = "instance1", CertificateId = 77, CertificateSource = "TEST", Domain = "new.example.com", CertificateStatus = "issued" } }, RequestId = "certificates" })
        });
        var result = await Aliyun(factory).ListAsync(Account("Aliyun"));
        Assert.True(result.Success);
        Assert.Equal(2, result.Data!.Count);
        Assert.True(result.Data.Single(x => x.Reference.ApiVersion == "V1").IsFree);
        Assert.True(result.Data.Single(x => x.Reference.ApiVersion == "V2").IsFree);
        Assert.Equal("77", result.Data.Single(x => x.Reference.ApiVersion == "V2").Reference.CertificateId);
    }

    [Theory]
    [InlineData("revoked", false)]
    [InlineData("expired", false)]
    [InlineData("revoked", true)]
    [InlineData("expired", true)]
    public async Task AliyunDoesNotSyncDeletedCertificatesFromClosedInstances(string certificateStatus, bool includeLegacyDuplicate)
    {
        var factory = new FakeFactory(input => input.Action switch
        {
            "ListUserCertificateOrder" => includeLegacyDuplicate
                ? Json(new { TotalCount = 1, CertificateOrderList = new[] { new { OrderId = 10, CertificateId = 123,
                    ProductCode = "digicert-free-1-free", Status = "REVOKED", Domain = "deleted.example.com" } }, RequestId = "orders" })
                : Json(new { TotalCount = 0, CertificateOrderList = Array.Empty<object>(), RequestId = "orders" }),
            "ListInstances" => Json(new { TotalCount = 1, InstanceList = new[] { new { InstanceId = "closed-instance",
                CertificateId = 123, InstanceType = "TEST", Spec = "ss.dv.t", Domain = "deleted.example.com",
                Status = "closed", CertificateStatus = certificateStatus } }, RequestId = "instances" }),
            "ListCertificates" => Json(new { TotalCount = 0, CertificateList = Array.Empty<object>(), RequestId = "certificates" }),
            _ => throw new InvalidOperationException("同步不应执行云端写操作。")
        });

        var result = await Aliyun(factory).ListAsync(Account("Aliyun"));

        Assert.True(result.Success);
        Assert.Empty(result.Data!);
    }

    [Fact]
    public async Task AliyunKeepsPendingApplicationsUnusedInstancesAndExistingHistoricalCertificates()
    {
        var factory = new FakeFactory(input => input.Action switch
        {
            "ListUserCertificateOrder" => Json(new { TotalCount = 0, CertificateOrderList = Array.Empty<object>(), RequestId = "orders" }),
            "ListInstances" => Json(new { TotalCount = 4, InstanceList = new[]
            {
                new { InstanceId = "unused", CertificateId = "", InstanceType = "TEST", Spec = "ss.dv.t", Domain = "", Status = "inactive", CertificateStatus = "" },
                new { InstanceId = "pending", CertificateId = "", InstanceType = "TEST", Spec = "ss.dv.t", Domain = "pending.example.com", Status = "pending", CertificateStatus = "" },
                new { InstanceId = "closed", CertificateId = "77", InstanceType = "TEST", Spec = "ss.dv.t", Domain = "closed.example.com", Status = "closed", CertificateStatus = "revoked" },
                new { InstanceId = "active", CertificateId = "90", InstanceType = "TEST", Spec = "ss.dv.t", Domain = "active.example.com", Status = "active", CertificateStatus = "issued" }
            }, RequestId = "instances" }),
            "ListCertificates" => Json(new { TotalCount = 3, CertificateList = new[]
            {
                new { InstanceId = "closed", CertificateId = "77", CertificateSource = "TEST", Domain = "closed.example.com", CertificateStatus = "revoked" },
                new { InstanceId = "closed", CertificateId = "70", CertificateSource = "TEST", Domain = "history.example.com", CertificateStatus = "expired" },
                new { InstanceId = "active", CertificateId = "90", CertificateSource = "TEST", Domain = "active.example.com", CertificateStatus = "issued" }
            }, RequestId = "certificates" }),
            _ => throw new InvalidOperationException("同步不应执行云端写操作。")
        });

        var result = await Aliyun(factory).ListAsync(Account("Aliyun"));

        Assert.True(result.Success);
        Assert.Equal(5, result.Data!.Count);
        Assert.Contains(result.Data, x => x.Reference.InstanceId == "unused" && x.Reference.CertificateId == "");
        Assert.Contains(result.Data, x => x.Reference.InstanceId == "pending" && x.Status == "Pending");
        Assert.Contains(result.Data, x => x.Reference.CertificateId == "77" && x.Status == "Revoked");
        Assert.Contains(result.Data, x => x.Reference.CertificateId == "70" && x.Status == "Expired");
        Assert.Contains(result.Data, x => x.Reference.CertificateId == "90" && x.Status == "Issued");
        Assert.All(result.Data, x => Assert.True(x.IsFree));
    }

    [Fact]
    public async Task AliyunDoesNotRestoreDeletedLatestCertificateWhenInstanceStillHasOtherHistory()
    {
        // 同一实例下仍有历史证书，不代表实例引用的另一张已删证书也存在。
        var factory = new FakeFactory(input => input.Action switch
        {
            "ListUserCertificateOrder" => Json(new { TotalCount = 0, CertificateOrderList = Array.Empty<object>(), RequestId = "orders" }),
            "ListInstances" => Json(new { TotalCount = 1, InstanceList = new[] { new { InstanceId = "instance1", CertificateId = 77,
                InstanceType = "TEST", Spec = "ss.dv.t", Domain = "deleted.example.com", Status = "closed", CertificateStatus = "revoked" } }, RequestId = "instances" }),
            "ListCertificates" => Json(new { TotalCount = 1, CertificateList = new[] { new { InstanceId = "instance1", CertificateId = 70,
                CertificateSource = "TEST", Domain = "history.example.com", CertificateStatus = "expired" } }, RequestId = "certificates" }),
            _ => throw new InvalidOperationException("同步不应执行云端写操作。")
        });

        var result = await Aliyun(factory).ListAsync(Account("Aliyun"));

        Assert.True(result.Success);
        var certificate = Assert.Single(result.Data!);
        Assert.Equal("70", certificate.Reference.CertificateId);
        Assert.Equal("Expired", certificate.Status);
    }

    [Fact]
    public async Task TencentDnsDeletionRequiresRecordInZoneAndSendsOnlyPreciseId()
    {
        var factory = new FakeFactory(r => r.Action == "DescribeRecordList"
            ? Json(new { Response = new { RecordCountInfo = new { TotalCount = 1, ListCount = 1 }, RecordList = new[] { new { RecordId = 88, Name = "_dnsauth", Type = "TXT", Value = "proof", TTL = 600, Status = "ENABLE" } }, RequestId = "records" } })
            : Json(new { Response = new { RequestId = "deleted" } }));
        var service = Tencent(factory);
        var absent = await service.DeleteRecordAsync(Account(), "example.com", "99");
        Assert.Equal("DnsRecordNotFound", absent.Code);
        Assert.DoesNotContain(factory.Requests, x => x.Action == "DeleteRecord");
        var deleted = await service.DeleteRecordAsync(Account(), "example.com", "88");
        Assert.True(deleted.Success);
        var input = factory.Requests.Single(x => x.Action == "DeleteRecord").Json;
        Assert.Equal(88, input.GetProperty("RecordId").GetInt64());
        Assert.Equal(2, input.EnumerateObject().Count());
    }

    [Fact]
    public async Task AliyunDnsDeletionIsSingleRecordAndMxIsMappedToPriority()
    {
        var factory = new FakeFactory(r => r.Action switch
        {
            "DescribeDomainRecords" => Json(new { TotalCount = 1, DomainRecords = new { Record = new[] { new { RecordId = "rec1", RR = "proof", Type = "TXT", Value = "value", TTL = 600, Status = "Enable" } } }, RequestId = "records" }),
            _ => Json(new { RecordId = "rec1", RequestId = "write" })
        });
        var service = Aliyun(factory);
        Assert.True((await service.CreateRecordAsync(Account("Aliyun"), "example.com", new("@", "MX", "mx.example.com", Mx: 10))).Success);
        Assert.Equal("10", factory.Requests.Single(x => x.Action == "AddDomainRecord").Fields["Priority"]);
        Assert.True((await service.DeleteRecordAsync(Account("Aliyun"), "example.com", "rec1")).Success);
        var deleted = factory.Requests.Single(x => x.Action == "DeleteDomainRecord");
        Assert.Equal("rec1", deleted.Fields["RecordId"]);
        Assert.DoesNotContain(factory.Requests, x => x.Action == "DeleteSubDomainRecords");
    }

    [Fact]
    public async Task AliyunRetriesFromFirstPageWhenRecordCountChangesAndReturnsCompleteSnapshot()
    {
        var calls = 0;
        var factory = new FakeFactory(_ =>
        {
            calls++;
            if (calls == 1)
                return Json(new { TotalCount = 2, DomainRecords = new { Record = new[] { new { RecordId = "rec1", RR = "a", Type = "A", Value = "192.0.2.1", TTL = 600, Status = "Enable" } } }, RequestId = "first" });
            if (calls == 2)
                return Json(new { TotalCount = 3, DomainRecords = new { Record = new[] { new { RecordId = "rec2", RR = "b", Type = "A", Value = "192.0.2.2", TTL = 600, Status = "Enable" } } }, RequestId = "changed" });
            return Json(new { TotalCount = 2, DomainRecords = new { Record = new[] {
                new { RecordId = "rec1", RR = "a", Type = "A", Value = "192.0.2.1", TTL = 600, Status = "Enable" },
                new { RecordId = "rec2", RR = "b", Type = "A", Value = "192.0.2.2", TTL = 600, Status = "Enable" },
            } }, RequestId = "stable" });
        });

        var result = await Aliyun(factory).ListRecordsAsync(Account("Aliyun"), "example.com");

        Assert.True(result.Success);
        Assert.Equal(2, result.Data!.Count);
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task ConnectivityTestsNeverWriteCloudResources()
    {
        var factory = new FakeFactory(_ => Json(new { Response = new { RequestId = "ok" } }));
        await Tencent(factory).TestAsync(Account());
        await Tencent(factory).TestDnsAsync(Account());
        Assert.Equal(new[] { "DescribeCertificates", "DescribeDomainList" }, factory.Requests.Select(x => x.Action));
    }

    [Theory]
    [InlineData("https://example.com/file.zip")]
    [InlineData("http://ssl.tencentcloudapi.com/file.zip")]
    [InlineData("https://cloud.tencent.com.evil.example/file.zip")]
    [InlineData("https://user@cloud.tencent.com/file.zip")]
    public void CertificateDownloadRejectsUnexpectedAddresses(string value)
        => Assert.False(CertificateDownloadHelper.IsAllowedTencentUrl(value, out _));

    [Fact]
    public void ZipDownloadRejectsPathTraversalWithoutWritingFiles()
    {
        using var bytes = new MemoryStream();
        using (var zip = new ZipArchive(bytes, ZipArchiveMode.Create, true))
        { using var writer = new StreamWriter(zip.CreateEntry("../private.key").Open()); writer.Write("secret"); }
        Assert.Equal("InvalidCertificatePackage", CertificateDownloadHelper.ValidateZip(bytes.ToArray()).Code);
    }

    [Fact]
    public void PemDownloadValidatesMatchingPrivateKeyAndExportsPfx()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
        var result = CertificateDownloadHelper.FromPem(cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem(), "123", "pfx", "download");
        Assert.True(result.Success);
        Assert.Equal("123.pfx", result.Data!.FileName);
        using var otherKey = RSA.Create(2048);
        var mismatch = CertificateDownloadHelper.FromPem(cert.ExportCertificatePem(), otherKey.ExportPkcs8PrivateKeyPem(), "123", "pem", "download");
        Assert.Equal("CertificateMaterialInvalid", mismatch.Code);
    }

    [Theory]
    [InlineData("www.example.com", "nginx", "www.example.com-nginx-20261015.zip")]
    [InlineData("api/example.com", "iis", "api_example.com-iis-20261015.zip")]
    public void UserDownloadFileNameUsesDomainFormatAndChinaDate(string domain, string format, string expected)
    {
        var actual = CertificateDownloadHelper.BuildFileName(domain, format, "cloud-id", new DateTimeOffset(2026, 10, 15, 1, 0, 0, TimeSpan.Zero));
        Assert.Equal(expected, actual);
    }

    private static TencentCloudService Tencent(FakeFactory factory) => new(new TencentCloudApiClient(factory), factory);
    private static AliyunCloudService Aliyun(FakeFactory factory) => new(new AliyunApiClient(factory));
    private static CloudAccountCredentials Account(string provider = "TencentCloud", string aliyunContactId = "") => new("account", "测试账户", provider,
        "test-access-id", "test-secret", true, true, true, "测试用户", "test@example.com", "13900000000", aliyunContactId);
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
    private sealed record Input(string Action, JsonElement Json, Dictionary<string, string> Fields);
    private sealed class FakeFactory(Func<Input, HttpResponseMessage> reply) : IHttpClientFactory
    {
        public List<Input> Requests { get; } = [];
        public HttpClient CreateClient(string name) => new(new Handler(this, reply)) { Timeout = TimeSpan.FromSeconds(10) };
        private sealed class Handler(FakeFactory owner, Func<Input, HttpResponseMessage> reply) : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var body = await request.Content!.ReadAsStringAsync(cancellationToken);
                var fields = new Dictionary<string, string>(); JsonElement json = default; string action;
                if (request.Headers.TryGetValues("X-TC-Action", out var actions))
                { action = actions.Single(); using var doc = JsonDocument.Parse(body); json = doc.RootElement.Clone(); }
                else
                {
                    foreach (var part in body.Split('&')) { var pair = part.Split('=', 2); fields[WebUtility.UrlDecode(pair[0])] = WebUtility.UrlDecode(pair.Length > 1 ? pair[1] : ""); }
                    action = fields["Action"];
                }
                var input = new Input(action, json, fields); owner.Requests.Add(input); return reply(input);
            }
        }
    }
}
