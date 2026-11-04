using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslManager.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCertificateSchedules : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CertificateScheduleRuns",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    ScheduleId = table.Column<string>(type: "TEXT", nullable: false),
                    TriggerKey = table.Column<string>(type: "TEXT", nullable: false),
                    ConfigSnapshotJson = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<string>(type: "TEXT", nullable: false),
                    TargetsJson = table.Column<string>(type: "TEXT", nullable: false),
                    OldCertificatesJson = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    Message = table.Column<string>(type: "TEXT", nullable: false),
                    Code = table.Column<string>(type: "TEXT", nullable: false),
                    CleanupStatus = table.Column<string>(type: "TEXT", nullable: false),
                    ScheduledForUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    FinishedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NextCheckAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LeaseUntilUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LeaseToken = table.Column<string>(type: "TEXT", nullable: false),
                    Active = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateScheduleRuns", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CertificateSchedules",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    AccountId = table.Column<string>(type: "TEXT", nullable: false),
                    Domain = table.Column<string>(type: "TEXT", nullable: false),
                    Alias = table.Column<string>(type: "TEXT", nullable: false),
                    ValidationMode = table.Column<string>(type: "TEXT", nullable: false),
                    AutoCleanup = table.Column<bool>(type: "INTEGER", nullable: false),
                    RevokeOldCertificates = table.Column<bool>(type: "INTEGER", nullable: false),
                    TargetIdsJson = table.Column<string>(type: "TEXT", nullable: false),
                    IntervalValue = table.Column<int>(type: "INTEGER", nullable: false),
                    IntervalUnit = table.Column<string>(type: "TEXT", nullable: false),
                    FirstRunAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    NextRunAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    ConfigRevision = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedByUserId = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateSchedules", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateScheduleRuns_Active_NextCheckAtUtc",
                table: "CertificateScheduleRuns",
                columns: new[] { "Active", "NextCheckAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateScheduleRuns_ScheduleId",
                table: "CertificateScheduleRuns",
                column: "ScheduleId",
                unique: true,
                filter: "Active = 1");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateScheduleRuns_ScheduleId_TriggerKey",
                table: "CertificateScheduleRuns",
                columns: new[] { "ScheduleId", "TriggerKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateSchedules_AccountId_Domain",
                table: "CertificateSchedules",
                columns: new[] { "AccountId", "Domain" },
                unique: true,
                filter: "Enabled = 1");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateSchedules_Enabled_NextRunAtUtc",
                table: "CertificateSchedules",
                columns: new[] { "Enabled", "NextRunAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CertificateScheduleRuns");

            migrationBuilder.DropTable(
                name: "CertificateSchedules");
        }
    }
}
