using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslManager.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAliyunContactId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AliyunContactId",
                table: "CloudAccounts",
                type: "TEXT",
                maxLength: 64,
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AliyunContactId",
                table: "CloudAccounts");
        }
    }
}
