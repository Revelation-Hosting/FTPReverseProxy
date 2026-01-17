using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FtpReverseProxy.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "BackendServers",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Host = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: false),
                    Protocol = table.Column<int>(type: "integer", nullable: false),
                    CredentialMapping = table.Column<int>(type: "integer", nullable: false),
                    ServiceAccountUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    ServiceAccountPassword = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    Description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    ConnectionTimeoutMs = table.Column<int>(type: "integer", nullable: false),
                    MaxConnections = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ModifiedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BackendServers", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RouteMappings",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Username = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    BackendServerId = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    BackendUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    BackendPassword = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    Priority = table.Column<int>(type: "integer", nullable: false),
                    Description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ModifiedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RouteMappings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RouteMappings_BackendServers_BackendServerId",
                        column: x => x.BackendServerId,
                        principalTable: "BackendServers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_BackendServers_IsEnabled",
                table: "BackendServers",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_BackendServers_Name",
                table: "BackendServers",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RouteMappings_BackendServerId",
                table: "RouteMappings",
                column: "BackendServerId");

            migrationBuilder.CreateIndex(
                name: "IX_RouteMappings_IsEnabled",
                table: "RouteMappings",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_RouteMappings_Username",
                table: "RouteMappings",
                column: "Username");

            migrationBuilder.CreateIndex(
                name: "IX_RouteMappings_Username_IsEnabled",
                table: "RouteMappings",
                columns: new[] { "Username", "IsEnabled" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RouteMappings");

            migrationBuilder.DropTable(
                name: "BackendServers");
        }
    }
}
