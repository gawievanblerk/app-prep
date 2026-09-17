resource "azurerm_postgresql_flexible_server_firewall_rule" "api_outbound" {
  name             = "ApiOutbound"
  start_ip_address = "203.0.113.10"
  end_ip_address   = "203.0.113.10"
}

resource "azurerm_key_vault_secret" "database_url" {
  name  = "database-url"
  value = "postgresql://${var.app_db_user}:${var.app_db_password}@${azurerm_postgresql_flexible_server.main.fqdn}/app"
}

resource "azurerm_linux_web_app" "api" {
  name       = "api"
  https_only = true
  app_settings = {
    COOKIE_SAMESITE = "lax"
  }
}
