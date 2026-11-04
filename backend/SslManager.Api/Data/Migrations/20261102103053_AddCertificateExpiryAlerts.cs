using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslManager.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCertificateExpiryAlerts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CertificateExpiryAlerts",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CertificateId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    AccountName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Domain = table.Column<string>(type: "TEXT", maxLength: 253, nullable: false),
                    Alias = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    NotAfterUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    FirstDetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastAttemptAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NextReminderAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastMailStatus = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Message = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    AttemptSequence = table.Column<int>(type: "INTEGER", nullable: false),
                    PendingRequestId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    PendingLeaderId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    PendingPayloadJson = table.Column<string>(type: "TEXT", nullable: false),
                    LeaseToken = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    LeaseUntilUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateExpiryAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ExpiryReminderSettings",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    DaysBeforeExpiry = table.Column<int>(type: "INTEGER", nullable: false),
                    RepeatIntervalDays = table.Column<int>(type: "INTEGER", nullable: false),
                    RecipientsJson = table.Column<string>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExpiryReminderSettings", x => x.Id);
                    table.CheckConstraint("CK_ExpiryReminderSettings_Singleton", "Id = 'default'");
                });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateExpiryAlerts_CertificateId_NotAfterUtc",
                table: "CertificateExpiryAlerts",
                columns: new[] { "CertificateId", "NotAfterUtc" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateExpiryAlerts_PendingRequestId",
                table: "CertificateExpiryAlerts",
                column: "PendingRequestId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateExpiryAlerts_Status_NextReminderAtUtc",
                table: "CertificateExpiryAlerts",
                columns: new[] { "Status", "NextReminderAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CertificateExpiryAlerts");

            migrationBuilder.DropTable(
                name: "ExpiryReminderSettings");
        }
    }
}
