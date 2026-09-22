resource "azurerm_postgresql_flexible_server_firewall_rule" "azure" {
  name             = "AllowAzureServices"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_key_vault_secret" "database_url" {
  name  = "database-url"
  value = "postgresql://${var.db_admin_username}:${var.db_admin_password}@${azurerm_postgresql_flexible_server.main.fqdn}/app"
}

resource "azurerm_linux_web_app" "api" {
  name = "api"
  app_settings = {
    COOKIE_SAMESITE = "none"
  }
}
