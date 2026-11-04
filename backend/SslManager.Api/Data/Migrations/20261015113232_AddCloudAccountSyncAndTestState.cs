using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslManager.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCloudAccountSyncAndTestState : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AutoSyncAtLocalTime",
                table: "CloudAccounts",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<bool>(
                name: "AutoSyncEnabled",
                table: "CloudAccounts",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "AutoSyncIntervalUnit",
                table: "CloudAccounts",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "AutoSyncIntervalValue",
                table: "CloudAccounts",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "AutoSyncNextRunAtUtc",
                table: "CloudAccounts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AutoSyncScope",
                table: "CloudAccounts",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "LastAutoSyncAtUtc",
                table: "CloudAccounts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastTestAtUtc",
                table: "CloudAccounts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastTestCode",
                table: "CloudAccounts",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "LastTestMessage",
                table: "CloudAccounts",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<bool>(
                name: "LastTestSuccess",
                table: "CloudAccounts",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AutoSyncAtLocalTime",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "AutoSyncEnabled",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "AutoSyncIntervalUnit",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "AutoSyncIntervalValue",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "AutoSyncNextRunAtUtc",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "AutoSyncScope",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "LastAutoSyncAtUtc",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "LastTestAtUtc",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "LastTestCode",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "LastTestMessage",
                table: "CloudAccounts");

            migrationBuilder.DropColumn(
                name: "LastTestSuccess",
                table: "CloudAccounts");
        }
    }
}
