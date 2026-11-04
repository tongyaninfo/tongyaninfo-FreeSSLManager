using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using SslManager.Api.Service;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;
using Microsoft.EntityFrameworkCore;
using ModelContextProtocol;

namespace SslManager.Api.Common.Mcp;

/// <summary>协议线格式交给官方 SDK，适配器只映射显式工具及统一业务结果。</summary>
public static class McpProtocolHandlers
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static async ValueTask<ListToolsResult> ListAsync(RequestContext<ListToolsRequestParams> request, CancellationToken ct)
    {
        var context = request.Services!.GetRequiredService<IHttpContextAccessor>().HttpContext!;
        var caller = McpBearerHandler.Caller(context);
        var log = context.RequestServices.GetRequiredService<IMcpInvocationLogService>();
        var invocationId = await log.StartAsync(caller, "tools/list", "", request.JsonRpcRequest.Id.ToString(),
            context.Request.Headers["MCP-Protocol-Version"].ToString(), ct);
        try
        {
            var tools = await context.RequestServices.GetRequiredService<IMcpToolDispatcher>().ListAsync(caller, ct);
            McpAuditCapture.SetOutput(context, JsonSerializer.SerializeToElement(new { tools = tools.Select(x => new { toolName = x.Name }) }));
            await log.CompleteAsync(invocationId, true, "OK", false, CancellationToken.None);
            return new() { Tools = tools.Select(tool => new Tool { Name = tool.Name, Title = tool.Title, Description = tool.Description,
                InputSchema = tool.InputSchema, OutputSchema = tool.OutputSchema,
                Annotations = new ToolAnnotations { ReadOnlyHint = tool.ReadOnly, DestructiveHint = !tool.ReadOnly,
                    OpenWorldHint = !tool.ReadOnly || tool.Name == "ssl_dns_records_list" } }).ToArray() };
        }
        catch (OperationCanceledException)
        { await log.CompleteAsync(invocationId, false, "CANCELLED", false, CancellationToken.None); throw; }
        catch
        { await log.CompleteAsync(invocationId, false, "SYSTEM_ERROR", false, CancellationToken.None); throw; }
    }
    public static async ValueTask<CallToolResult> CallAsync(RequestContext<CallToolRequestParams> request, CancellationToken ct)
    {
        var context = request.Services!.GetRequiredService<IHttpContextAccessor>().HttpContext!;
        var services = context.RequestServices;
        var caller = McpBearerHandler.Caller(context);
        var logger = services.GetRequiredService<IMcpInvocationLogService>();
        var name = request.Params?.Name ?? "";
        var descriptor = McpToolCatalog.All.FirstOrDefault(tool => tool.Name == name);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(descriptor?.ReadOnly == true ? 30 : 120));
        var id = await logger.StartAsync(caller, "tools/call", descriptor?.Name ?? "unknown", request.JsonRpcRequest.Id.ToString(),
            context.Request.Headers["MCP-Protocol-Version"].ToString(), ct);
        try
        {
            if (descriptor is null) throw new McpProtocolException("工具不存在。", McpErrorCode.InvalidParams);
            var arguments = JsonSerializer.SerializeToElement(request.Params?.Arguments, Json);
            McpAuditCapture.SetInput(context, name, arguments);
            if (arguments.ValueKind == JsonValueKind.Null) arguments = JsonSerializer.SerializeToElement(new { });
            var db = services.GetRequiredService<AppDbContext>();
            var entry = await db.McpInvocationLogs.FindAsync([id], ct);
            entry!.ArgumentsDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(arguments.GetRawText())));
            var permission = await services.GetRequiredService<IMcpAuthorizationService>().AuthorizeAsync(caller, name, null, false, deadline.Token);
            if (permission.Success) entry.PolicyRevision = permission.Data!.PolicyRevision;
            if (arguments.TryGetProperty("idempotencyKey", out var key) && key.ValueKind == JsonValueKind.String)
            {
                var existing = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(operation => operation.ClientId == caller.ClientId
                    && operation.IdempotencyKey == key.GetString(), deadline.Token);
                entry.IdempotencyReused = existing is not null && (name.EndsWith("_prepare", StringComparison.Ordinal) || name == "ssl_deployment_plan"
                    || existing.ConsumedAtUtc.HasValue);
            }
            await db.SaveChangesAsync(ct);
            var result = await services.GetRequiredService<IMcpToolDispatcher>().CallAsync(caller, name, arguments, deadline.Token);
            entry.IdempotencyReused &= result.Success;
            McpAuditCapture.SetOutput(context, JsonSerializer.SerializeToElement(result, Json));
            if (result.Code == "INVALID_ARGUMENTS") throw new McpProtocolException("工具参数不符合输入规范。", McpErrorCode.InvalidParams);
            if (result.Data is McpOperationView operation)
            {
                entry.OperationId = operation.Id; entry.CertificateId = operation.CertificateId;
                entry.BatchId = operation.BatchId; entry.TaskId = operation.TaskId;
            }
            await logger.CompleteAsync(id, result.Success, result.Code, false, CancellationToken.None);
            return new() { IsError = !result.Success, StructuredContent = JsonSerializer.SerializeToElement(result, Json),
                Content = [new TextContentBlock { Text = result.Message }] };
        }
        catch (McpProtocolException)
        {
            McpAuditCapture.SetOutput(context, JsonSerializer.SerializeToElement(new { success = false, code = "INVALID_ARGUMENTS" }));
            await logger.CompleteAsync(id, false, "INVALID_ARGUMENTS", false, CancellationToken.None);
            throw;
        }
        catch (OperationCanceledException)
        {
            McpAuditCapture.SetOutput(context, JsonSerializer.SerializeToElement(new { success = false, code = ct.IsCancellationRequested ? "CANCELLED" : "TIMEOUT" }));
            await logger.CompleteAsync(id, false, ct.IsCancellationRequested ? "CANCELLED" : "TIMEOUT", descriptor?.ReadOnly != true, CancellationToken.None);
            throw;
        }
        catch (Exception)
        {
            McpAuditCapture.SetOutput(context, JsonSerializer.SerializeToElement(new { success = false, code = "SYSTEM_ERROR" }));
            await logger.CompleteAsync(id, false, "SYSTEM_ERROR", true, CancellationToken.None);
            return new() { IsError = true, Content = [new TextContentBlock { Text = "工具处理异常，请通过调用标识查询业务状态。" }] };
        }
    }
}
