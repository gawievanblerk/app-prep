from tests.reviews.helpers import findings_for, write

AZURE = """
resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure" {
  name             = "AllowAzureServices"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}
resource "azurerm_postgresql_flexible_server_firewall_rule" "office" {
  start_ip_address = "203.0.113.10"
  end_ip_address   = "203.0.113.10"
}
resource "azurerm_mysql_flexible_server_firewall_rule" "everyone" {
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
resource "azurerm_key_vault_secret" "database_url" {
  value = "postgresql://${var.db_admin_username}:${var.db_admin_password}@${azurerm_postgresql_flexible_server.main.fqdn}/app"
}
resource "azurerm_key_vault_secret" "app_url" {
  value = "postgresql://${var.app_db_user}:${var.app_db_password}@db/app"
}
resource "azurerm_linux_web_app" "api" {
  name = "api"
  site_config {
    always_on = true
  }
}
resource "azurerm_linux_web_app" "safe" {
  https_only = true
}
"""

AWS = """
resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
}
resource "aws_cloudfront_distribution" "cdn" {
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
}
resource "aws_lb_listener" "http" {
  protocol = "HTTP"
  default_action {
    type = "redirect"
  }
}
"""


def test_database_network_rules(tmp_path):
    write(tmp_path, "infra/azure.tf", AZURE)
    write(tmp_path, "infra/aws.tf", AWS)
    found = findings_for(tmp_path, "baseline", "BASE-DB-NETWORK-OPEN")
    assert sorted((str(f.locations[0]), f.severity.value) for f in found) == [
        ("infra/aws.tf:19", "medium"),
        ("infra/aws.tf:2", "high"),
        ("infra/azure.tf:11", "high"),
        ("infra/azure.tf:2", "medium"),
    ]
    assert all(f.tag.value == "CONFIRMED" for f in found)


def test_admin_login_connection_string(tmp_path):
    write(tmp_path, "infra/azure.tf", AZURE)
    [f] = findings_for(tmp_path, "baseline", "BASE-DB-ADMIN-LOGIN")
    assert str(f.locations[0]) == "infra/azure.tf:16"
    assert "var.db_admin_username" in f.detail and f.proof_needed


def test_https_not_enforced(tmp_path):
    write(tmp_path, "infra/azure.tf", AZURE)
    write(tmp_path, "infra/aws.tf", AWS)
    found = findings_for(tmp_path, "baseline", "BASE-HTTPS-NOT-ENFORCED")
    assert sorted(str(f.locations[0]) for f in found) == ["infra/aws.tf:21", "infra/azure.tf:21"]
