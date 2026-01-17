using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FtpReverseProxy.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSniCertificateFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ClientCertificatePassword",
                table: "BackendServers",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ClientCertificatePath",
                table: "BackendServers",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ClientFacingHostnames",
                table: "BackendServers",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ClientCertificatePassword",
                table: "BackendServers");

            migrationBuilder.DropColumn(
                name: "ClientCertificatePath",
                table: "BackendServers");

            migrationBuilder.DropColumn(
                name: "ClientFacingHostnames",
                table: "BackendServers");
        }
    }
}
