using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslManager.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCloudflareAcmeIssuance : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // 两种账号接入均由用户选择，自动模式只在独立注册动作下创建外部账号。
            migrationBuilder.AddColumn<string>(name: "AcmeAccountMode", table: "CloudAccounts", type: "TEXT", maxLength: 20, nullable: false, defaultValue: "Existing");
            migrationBuilder.AddColumn<string>(name: "AcmeRegistrationStatus", table: "CloudAccounts", type: "TEXT", maxLength: 30, nullable: false, defaultValue: "");
            migrationBuilder.AddColumn<DateTime>(name: "AcmeRegisteredAtUtc", table: "CloudAccounts", type: "TEXT", nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AcmeDirectoryUrl",
                table: "CloudAccounts",
                type: "TEXT",
                maxLength: 300,
                nullable: false,
                defaultValue: "https://acme-v02.api.letsencrypt.org/directory");

migrationBuilder.AddColumn<string>(
                name: "DnsZoneId",
                table: "CertificateSchedules",
                type: "TEXT",
                nullable: true);

migrationBuilder.AddColumn<bool>(
                name: "HasPrivateKey",
                table: "Certificates",
                type: "INTEGER",
                nullable: false,
                defaultValue: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsStaging",
                table: "Certificates",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

migrationBuilder.CreateTable(
                name: "CertificateIssuanceStates",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    AccountId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Provider = table.Column<string>(type: "TEXT", maxLength: 30, nullable: false),
                    Domain = table.Column<string>(type: "TEXT", maxLength: 254, nullable: false),
                    Stage = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    RemoteCertificateId = table.Column<string>(type: "TEXT", nullable: false),
                    AcmeAccountUrl = table.Column<string>(type: "TEXT", nullable: false),
                    AccountKeyThumbprint = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    OrderUrl = table.Column<string>(type: "TEXT", nullable: false),
                    FinalizeUrl = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateUrl = table.Column<string>(type: "TEXT", nullable: false),
                    AuthorizationsJson = table.Column<string>(type: "TEXT", nullable: false),
                    IsStaging = table.Column<bool>(type: "INTEGER", nullable: false),
                    ProtectedPayload = table.Column<string>(type: "TEXT", nullable: false),
                    Revision = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateIssuanceStates", x => x.Id);
                });

migrationBuilder.CreateIndex(
                name: "IX_CertificateIssuanceStates_AccountId_Provider",
                table: "CertificateIssuanceStates",
                columns: new[] { "AccountId", "Provider" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateIssuanceStates_OrderUrl",
                table: "CertificateIssuanceStates",
                column: "OrderUrl",
                unique: true,
                filter: "OrderUrl <> ''");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(name: "AcmeAccountMode", table: "CloudAccounts");
            migrationBuilder.DropColumn(name: "AcmeRegistrationStatus", table: "CloudAccounts");
            migrationBuilder.DropColumn(name: "AcmeRegisteredAtUtc", table: "CloudAccounts");

migrationBuilder.DropTable(
                name: "CertificateIssuanceStates");

            migrationBuilder.DropColumn(
                name: "AcmeDirectoryUrl",
                table: "CloudAccounts");

migrationBuilder.DropColumn(
                name: "DnsZoneId",
                table: "CertificateSchedules");

migrationBuilder.DropColumn(
                name: "HasPrivateKey",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "IsStaging",
                table: "Certificates");
        }
    }
}
