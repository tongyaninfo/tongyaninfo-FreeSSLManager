using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslManager.Api.Data.Migrations
{
    /// <summary>增量增加 API Key、调用审计及实例身份；旧 OAuth 记录保留原授权语义，不生成凭据。</summary>
    public partial class AddMcpApiKeysAndAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "InstanceId",
                table: "McpSettings",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "SystemName",
                table: "McpSettings",
                type: "TEXT",
                nullable: false,
                defaultValue:"Free SSL Manager");

            migrationBuilder.AddColumn<string>(
                name: "ApiKeyId",
                table: "McpOperations",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "AuthenticationType",
                table: "McpOperations",
                type: "TEXT",
                nullable: false,
                defaultValue:"OAuth");

            migrationBuilder.AddColumn<string>(
                name: "ApiKeyId",
                table: "McpInvocationLogs",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ApiKeyName",
                table: "McpInvocationLogs",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ApiKeyPrefix",
                table: "McpInvocationLogs",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "AuthenticationType",
                table: "McpInvocationLogs",
                type: "TEXT",
                nullable: false,
                defaultValue:"OAuth");

            migrationBuilder.AddColumn<string>(
                name: "ContextJson",
                table: "McpInvocationLogs",
                type: "TEXT",
                nullable: false,
                defaultValue:"{}");

            migrationBuilder.CreateTable(
                name: "McpApiKeys",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    Prefix = table.Column<string>(type: "TEXT", nullable: false),
                    SecretHash = table.Column<string>(type: "TEXT", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastUsedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RevokedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ConfigRevision = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpApiKeys", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_McpInvocationLogs_ApiKeyId_StartedAtUtc",
                table: "McpInvocationLogs",
                columns: new[] { "ApiKeyId", "StartedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_McpApiKeys_ClientId",
                table: "McpApiKeys",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_McpApiKeys_Prefix",
                table: "McpApiKeys",
                column: "Prefix",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "McpApiKeys");

            migrationBuilder.DropIndex(
                name: "IX_McpInvocationLogs_ApiKeyId_StartedAtUtc",
                table: "McpInvocationLogs");

            migrationBuilder.DropColumn(
                name: "InstanceId",
                table: "McpSettings");

            migrationBuilder.DropColumn(
                name: "SystemName",
                table: "McpSettings");

            migrationBuilder.DropColumn(
                name: "ApiKeyId",
                table: "McpOperations");

            migrationBuilder.DropColumn(
                name: "AuthenticationType",
                table: "McpOperations");

            migrationBuilder.DropColumn(
                name: "ApiKeyId",
                table: "McpInvocationLogs");

            migrationBuilder.DropColumn(
                name: "ApiKeyName",
                table: "McpInvocationLogs");

            migrationBuilder.DropColumn(
                name: "ApiKeyPrefix",
                table: "McpInvocationLogs");

            migrationBuilder.DropColumn(
                name: "AuthenticationType",
                table: "McpInvocationLogs");

            migrationBuilder.DropColumn(
                name: "ContextJson",
                table: "McpInvocationLogs");
        }
    }
}
