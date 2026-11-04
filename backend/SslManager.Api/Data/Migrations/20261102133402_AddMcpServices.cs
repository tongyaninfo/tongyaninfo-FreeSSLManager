using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslManager.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddMcpServices : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "McpAllowRules",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", nullable: false),
                    ToolNamesJson = table.Column<string>(type: "TEXT", nullable: false),
                    AccountIdsJson = table.Column<string>(type: "TEXT", nullable: false),
                    DomainsJson = table.Column<string>(type: "TEXT", nullable: false),
                    TargetIdsJson = table.Column<string>(type: "TEXT", nullable: false),
                    AllowedCidrsJson = table.Column<string>(type: "TEXT", nullable: false),
                    ScopesJson = table.Column<string>(type: "TEXT", nullable: false),
                    AllAccounts = table.Column<bool>(type: "INTEGER", nullable: false),
                    AllDomains = table.Column<bool>(type: "INTEGER", nullable: false),
                    AllTargets = table.Column<bool>(type: "INTEGER", nullable: false),
                    ApprovalMode = table.Column<string>(type: "TEXT", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ConfigRevision = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpAllowRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "McpClients",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    OAuthApplicationId = table.Column<string>(type: "TEXT", nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    ClientType = table.Column<string>(type: "TEXT", nullable: false),
                    GrantType = table.Column<string>(type: "TEXT", nullable: false),
                    BoundUserId = table.Column<string>(type: "TEXT", nullable: false),
                    ScopesJson = table.Column<string>(type: "TEXT", nullable: false),
                    RedirectUrisJson = table.Column<string>(type: "TEXT", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ConfigRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastUsedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpClients", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "McpInvocationLogs",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    TraceId = table.Column<string>(type: "TEXT", nullable: false),
                    RequestId = table.Column<string>(type: "TEXT", nullable: false),
                    ProtocolVersion = table.Column<string>(type: "TEXT", nullable: false),
                    Method = table.Column<string>(type: "TEXT", nullable: false),
                    ToolName = table.Column<string>(type: "TEXT", nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", nullable: false),
                    UserId = table.Column<string>(type: "TEXT", nullable: false),
                    AuthorizationId = table.Column<string>(type: "TEXT", nullable: false),
                    RemoteIp = table.Column<string>(type: "TEXT", nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    Code = table.Column<string>(type: "TEXT", nullable: false),
                    Message = table.Column<string>(type: "TEXT", nullable: false),
                    ArgumentsDigest = table.Column<string>(type: "TEXT", nullable: false),
                    OperationId = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<string>(type: "TEXT", nullable: false),
                    BatchId = table.Column<string>(type: "TEXT", nullable: false),
                    TaskId = table.Column<string>(type: "TEXT", nullable: false),
                    IdempotencyReused = table.Column<bool>(type: "INTEGER", nullable: false),
                    PolicyRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    HttpStatus = table.Column<int>(type: "INTEGER", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    FinishedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DurationMilliseconds = table.Column<long>(type: "INTEGER", nullable: false),
                    OccurrenceCount = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpInvocationLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "McpOAuthApplications",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    ApplicationType = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    ClientSecret = table.Column<string>(type: "TEXT", nullable: true),
                    ClientType = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    ConcurrencyToken = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    ConsentType = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    DisplayName = table.Column<string>(type: "TEXT", nullable: true),
                    DisplayNames = table.Column<string>(type: "TEXT", nullable: true),
                    JsonWebKeySet = table.Column<string>(type: "TEXT", nullable: true),
                    Permissions = table.Column<string>(type: "TEXT", nullable: true),
                    PostLogoutRedirectUris = table.Column<string>(type: "TEXT", nullable: true),
                    Properties = table.Column<string>(type: "TEXT", nullable: true),
                    RedirectUris = table.Column<string>(type: "TEXT", nullable: true),
                    Requirements = table.Column<string>(type: "TEXT", nullable: true),
                    Settings = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpOAuthApplications", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "McpOAuthScopes",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    ConcurrencyToken = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    Description = table.Column<string>(type: "TEXT", nullable: true),
                    Descriptions = table.Column<string>(type: "TEXT", nullable: true),
                    DisplayName = table.Column<string>(type: "TEXT", nullable: true),
                    DisplayNames = table.Column<string>(type: "TEXT", nullable: true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Properties = table.Column<string>(type: "TEXT", nullable: true),
                    Resources = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpOAuthScopes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "McpOperations",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", nullable: false),
                    AuthorizationId = table.Column<string>(type: "TEXT", nullable: false),
                    EffectiveUserId = table.Column<string>(type: "TEXT", nullable: false),
                    PreparedBy = table.Column<string>(type: "TEXT", nullable: false),
                    ApprovedBy = table.Column<string>(type: "TEXT", nullable: false),
                    ToolName = table.Column<string>(type: "TEXT", nullable: false),
                    Kind = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    IdempotencyKey = table.Column<string>(type: "TEXT", nullable: false),
                    ArgumentsJson = table.Column<string>(type: "TEXT", nullable: false),
                    ArgumentsDigest = table.Column<string>(type: "TEXT", nullable: false),
                    ResourceJson = table.Column<string>(type: "TEXT", nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", nullable: false),
                    ScopesJson = table.Column<string>(type: "TEXT", nullable: false),
                    PolicyRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    SettingsRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    ClientRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    ApprovalExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ApprovedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ConsumedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CertificateId = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateJobId = table.Column<string>(type: "TEXT", nullable: false),
                    BatchId = table.Column<string>(type: "TEXT", nullable: false),
                    TaskId = table.Column<string>(type: "TEXT", nullable: false),
                    PlanRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    LeaseToken = table.Column<string>(type: "TEXT", nullable: false),
                    LeaseUntilUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NextRunAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Version = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Message = table.Column<string>(type: "TEXT", nullable: false),
                    Code = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpOperations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "McpSettings",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    PublicBaseUrl = table.Column<string>(type: "TEXT", nullable: false),
                    Mode = table.Column<string>(type: "TEXT", nullable: false),
                    AllowedCidrsJson = table.Column<string>(type: "TEXT", nullable: false),
                    AllowedOriginsJson = table.Column<string>(type: "TEXT", nullable: false),
                    AllowedToolsJson = table.Column<string>(type: "TEXT", nullable: false),
                    RateLimitPerMinute = table.Column<int>(type: "INTEGER", nullable: false),
                    MaxConcurrentCalls = table.Column<int>(type: "INTEGER", nullable: false),
                    LogRetentionDays = table.Column<int>(type: "INTEGER", nullable: false),
                    ConfigRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpSettings", x => x.Id);
                    table.CheckConstraint("CK_McpSettings_Singleton", "Id = 'default'");
                });

            migrationBuilder.CreateTable(
                name: "McpOAuthAuthorizations",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    ApplicationId = table.Column<string>(type: "TEXT", nullable: true),
                    ConcurrencyToken = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    CreationDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Properties = table.Column<string>(type: "TEXT", nullable: true),
                    Scopes = table.Column<string>(type: "TEXT", nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 400, nullable: true),
                    Type = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpOAuthAuthorizations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_McpOAuthAuthorizations_McpOAuthApplications_ApplicationId",
                        column: x => x.ApplicationId,
                        principalTable: "McpOAuthApplications",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "McpOAuthTokens",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    ApplicationId = table.Column<string>(type: "TEXT", nullable: true),
                    AuthorizationId = table.Column<string>(type: "TEXT", nullable: true),
                    ConcurrencyToken = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    CreationDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ExpirationDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Payload = table.Column<string>(type: "TEXT", nullable: true),
                    Properties = table.Column<string>(type: "TEXT", nullable: true),
                    RedemptionDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ReferenceId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 400, nullable: true),
                    Type = table.Column<string>(type: "TEXT", maxLength: 150, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpOAuthTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_McpOAuthTokens_McpOAuthApplications_ApplicationId",
                        column: x => x.ApplicationId,
                        principalTable: "McpOAuthApplications",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_McpOAuthTokens_McpOAuthAuthorizations_AuthorizationId",
                        column: x => x.AuthorizationId,
                        principalTable: "McpOAuthAuthorizations",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_McpAllowRules_ClientId",
                table: "McpAllowRules",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_McpClients_ClientId",
                table: "McpClients",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_McpClients_OAuthApplicationId",
                table: "McpClients",
                column: "OAuthApplicationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_McpInvocationLogs_ClientId_StartedAtUtc",
                table: "McpInvocationLogs",
                columns: new[] { "ClientId", "StartedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_McpInvocationLogs_OperationId",
                table: "McpInvocationLogs",
                column: "OperationId");

            migrationBuilder.CreateIndex(
                name: "IX_McpInvocationLogs_StartedAtUtc",
                table: "McpInvocationLogs",
                column: "StartedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_McpInvocationLogs_StartedAtUtc_Code_Status",
                table: "McpInvocationLogs",
                columns: new[] { "StartedAtUtc", "Code", "Status" },
                unique: true,
                filter: "Status = 'Denied' AND ClientId = ''");

            migrationBuilder.CreateIndex(
                name: "IX_McpInvocationLogs_ToolName_StartedAtUtc",
                table: "McpInvocationLogs",
                columns: new[] { "ToolName", "StartedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_McpOAuthApplications_ClientId",
                table: "McpOAuthApplications",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_McpOAuthAuthorizations_ApplicationId_Status_Subject_Type",
                table: "McpOAuthAuthorizations",
                columns: new[] { "ApplicationId", "Status", "Subject", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_McpOAuthScopes_Name",
                table: "McpOAuthScopes",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_McpOAuthTokens_ApplicationId_Status_Subject_Type",
                table: "McpOAuthTokens",
                columns: new[] { "ApplicationId", "Status", "Subject", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_McpOAuthTokens_AuthorizationId",
                table: "McpOAuthTokens",
                column: "AuthorizationId");

            migrationBuilder.CreateIndex(
                name: "IX_McpOAuthTokens_ReferenceId",
                table: "McpOAuthTokens",
                column: "ReferenceId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_McpOperations_BatchId",
                table: "McpOperations",
                column: "BatchId");

            migrationBuilder.CreateIndex(
                name: "IX_McpOperations_CertificateId",
                table: "McpOperations",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_McpOperations_ClientId_IdempotencyKey",
                table: "McpOperations",
                columns: new[] { "ClientId", "IdempotencyKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_McpOperations_Status_NextRunAtUtc",
                table: "McpOperations",
                columns: new[] { "Status", "NextRunAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "McpAllowRules");

            migrationBuilder.DropTable(
                name: "McpClients");

            migrationBuilder.DropTable(
                name: "McpInvocationLogs");

            migrationBuilder.DropTable(
                name: "McpOAuthScopes");

            migrationBuilder.DropTable(
                name: "McpOAuthTokens");

            migrationBuilder.DropTable(
                name: "McpOperations");

            migrationBuilder.DropTable(
                name: "McpSettings");

            migrationBuilder.DropTable(
                name: "McpOAuthAuthorizations");

            migrationBuilder.DropTable(
                name: "McpOAuthApplications");
        }
    }
}
