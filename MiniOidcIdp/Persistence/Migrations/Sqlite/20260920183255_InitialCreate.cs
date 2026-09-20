using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MiniOidcIdp.Persistence.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuthorizationCodes",
                columns: table => new
                {
                    CodeHash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    SessionJson = table.Column<string>(type: "TEXT", nullable: false),
                    ExpiresAtUnix = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationCodes", x => x.CodeHash);
                });

            migrationBuilder.CreateTable(
                name: "Clients",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    RedirectUrisJson = table.Column<string>(type: "TEXT", nullable: false),
                    PostLogoutRedirectUrisJson = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUnix = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Clients", x => x.ClientId);
                });

            migrationBuilder.CreateTable(
                name: "DataProtectionKeys",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    FriendlyName = table.Column<string>(type: "TEXT", nullable: true),
                    Xml = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DataProtectionKeys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    TokenHash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    FamilyId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    SessionJson = table.Column<string>(type: "TEXT", nullable: false),
                    IssuedAtUnix = table.Column<long>(type: "INTEGER", nullable: false),
                    FamilyCreatedAtUnix = table.Column<long>(type: "INTEGER", nullable: false),
                    ExpiresAtUnix = table.Column<long>(type: "INTEGER", nullable: false),
                    Used = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.TokenHash);
                });

            migrationBuilder.CreateTable(
                name: "RoleMappings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    GroupName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Role = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RoleMappings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Settings",
                columns: table => new
                {
                    Key = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Value = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Settings", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "SigningKeys",
                columns: table => new
                {
                    Kid = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedAtUnix = table.Column<long>(type: "INTEGER", nullable: false),
                    EncryptedPrivateKey = table.Column<byte[]>(type: "BLOB", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SigningKeys", x => x.Kid);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCodes_ExpiresAtUnix",
                table: "AuthorizationCodes",
                column: "ExpiresAtUnix");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_ExpiresAtUnix",
                table: "RefreshTokens",
                column: "ExpiresAtUnix");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_FamilyId",
                table: "RefreshTokens",
                column: "FamilyId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_Subject",
                table: "RefreshTokens",
                column: "Subject");

            migrationBuilder.CreateIndex(
                name: "IX_RoleMappings_GroupName_Role",
                table: "RoleMappings",
                columns: new[] { "GroupName", "Role" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuthorizationCodes");

            migrationBuilder.DropTable(
                name: "Clients");

            migrationBuilder.DropTable(
                name: "DataProtectionKeys");

            migrationBuilder.DropTable(
                name: "RefreshTokens");

            migrationBuilder.DropTable(
                name: "RoleMappings");

            migrationBuilder.DropTable(
                name: "Settings");

            migrationBuilder.DropTable(
                name: "SigningKeys");
        }
    }
}
