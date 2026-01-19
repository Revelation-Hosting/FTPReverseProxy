using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FtpReverseProxy.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPublicKeyToRouteMapping : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PublicKey",
                table: "RouteMappings",
                type: "character varying(1000)",
                maxLength: 1000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PublicKey",
                table: "RouteMappings");
        }
    }
}
