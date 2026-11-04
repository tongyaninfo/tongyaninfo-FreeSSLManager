using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslManager.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDeploymentTargets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeploymentBatches",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateDomain = table.Column<string>(type: "TEXT", nullable: false),
                    Fingerprint = table.Column<string>(type: "TEXT", nullable: false),
                    MaterialDigest = table.Column<string>(type: "TEXT", nullable: false),
                    MaterialSnapshotId = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    IdempotencyKey = table.Column<string>(type: "TEXT", nullable: false),
                    PlanRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    SubmittedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentBatches", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentBindings",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    TargetId = table.Column<string>(type: "TEXT", nullable: false),
                    ResourceKey = table.Column<string>(type: "TEXT", nullable: false),
                    RemoteResourceId = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<string>(type: "TEXT", nullable: false),
                    Fingerprint = table.Column<string>(type: "TEXT", nullable: false),
                    MaterialDigest = table.Column<string>(type: "TEXT", nullable: false),
                    LastTaskId = table.Column<string>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentBindings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentMaterialSnapshots",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<string>(type: "TEXT", nullable: false),
                    MetadataJson = table.Column<string>(type: "TEXT", nullable: false),
                    ProtectedPayload = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentMaterialSnapshots", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentTargets",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    ExecutorKey = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    ExecutorRevision = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    Endpoint = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    Port = table.Column<int>(type: "INTEGER", nullable: false),
                    Username = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    AuthenticationMode = table.Column<string>(type: "TEXT", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    TlsFingerprint = table.Column<string>(type: "TEXT", nullable: false),
                    ConfigurationJson = table.Column<string>(type: "TEXT", nullable: false),
                    ProtectedCredentials = table.Column<string>(type: "TEXT", nullable: false),
                    ConfigRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastTestAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastTestSuccess = table.Column<bool>(type: "INTEGER", nullable: true),
                    LastTestMessage = table.Column<string>(type: "TEXT", nullable: false),
                    ProductVersion = table.Column<string>(type: "TEXT", nullable: false),
                    LastDeploymentAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastDeploymentStatus = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentTargets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentTasks",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    BatchId = table.Column<string>(type: "TEXT", nullable: false),
                    TargetId = table.Column<string>(type: "TEXT", nullable: false),
                    TargetName = table.Column<string>(type: "TEXT", nullable: false),
                    ExecutorKey = table.Column<string>(type: "TEXT", nullable: false),
                    ExecutorRevision = table.Column<string>(type: "TEXT", nullable: false),
                    ConfigRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    Phase = table.Column<string>(type: "TEXT", nullable: false),
                    Message = table.Column<string>(type: "TEXT", nullable: false),
                    Code = table.Column<string>(type: "TEXT", nullable: false),
                    ResourceKey = table.Column<string>(type: "TEXT", nullable: false),
                    TargetSnapshotJson = table.Column<string>(type: "TEXT", nullable: false),
                    ProtectedCredentials = table.Column<string>(type: "TEXT", nullable: false),
                    PlanJson = table.Column<string>(type: "TEXT", nullable: false),
                    MaterialSnapshotId = table.Column<string>(type: "TEXT", nullable: false),
                    Fingerprint = table.Column<string>(type: "TEXT", nullable: false),
                    VerificationLevel = table.Column<string>(type: "TEXT", nullable: false),
                    RemoteResourceId = table.Column<string>(type: "TEXT", nullable: false),
                    ReceiptJson = table.Column<string>(type: "TEXT", nullable: false),
                    LeaseId = table.Column<string>(type: "TEXT", nullable: false),
                    LeaseUntilUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CancelRequested = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    FinishedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentTasks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentTaskSteps",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    TaskId = table.Column<string>(type: "TEXT", nullable: false),
                    Phase = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    Message = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentTaskSteps", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentBatches_IdempotencyKey",
                table: "DeploymentBatches",
                column: "IdempotencyKey",
                unique: true,
                filter: "IdempotencyKey <> ''");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentBindings_TargetId_ResourceKey",
                table: "DeploymentBindings",
                columns: new[] { "TargetId", "ResourceKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentTasks_BatchId",
                table: "DeploymentTasks",
                column: "BatchId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentTasks_ResourceKey_Status",
                table: "DeploymentTasks",
                columns: new[] { "ResourceKey", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentTasks_Status_CreatedAtUtc",
                table: "DeploymentTasks",
                columns: new[] { "Status", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentTaskSteps_TaskId_CreatedAtUtc",
                table: "DeploymentTaskSteps",
                columns: new[] { "TaskId", "CreatedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeploymentBatches");

            migrationBuilder.DropTable(
                name: "DeploymentBindings");

            migrationBuilder.DropTable(
                name: "DeploymentMaterialSnapshots");

            migrationBuilder.DropTable(
                name: "DeploymentTargets");

            migrationBuilder.DropTable(
                name: "DeploymentTasks");

            migrationBuilder.DropTable(
                name: "DeploymentTaskSteps");
        }
    }
}
