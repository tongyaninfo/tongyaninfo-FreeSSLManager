using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslManager.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddMailSending : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "MailMessages",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    RequestId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ToJson = table.Column<string>(type: "TEXT", nullable: false),
                    FromAddress = table.Column<string>(type: "TEXT", maxLength: 254, nullable: false),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    Body = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Code = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Message = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    CreatedByUserId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedByName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    MessageId = table.Column<string>(type: "TEXT", maxLength: 254, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MailMessages", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MailSettings",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    Host = table.Column<string>(type: "TEXT", maxLength: 253, nullable: false),
                    Port = table.Column<int>(type: "INTEGER", nullable: false),
                    Security = table.Column<string>(type: "TEXT", maxLength: 30, nullable: false),
                    Username = table.Column<string>(type: "TEXT", maxLength: 254, nullable: false),
                    FromAddress = table.Column<string>(type: "TEXT", maxLength: 254, nullable: false),
                    FromName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    ProtectedPassword = table.Column<string>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MailSettings", x => x.Id);
                    table.CheckConstraint("CK_MailSettings_Singleton", "Id = 'default'");
                });

            migrationBuilder.CreateIndex(
                name: "IX_MailMessages_CreatedAtUtc",
                table: "MailMessages",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_MailMessages_RequestId",
                table: "MailMessages",
                column: "RequestId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MailMessages_Status_CreatedAtUtc",
                table: "MailMessages",
                columns: new[] { "Status", "CreatedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MailMessages");

            migrationBuilder.DropTable(
                name: "MailSettings");
        }
    }
}
