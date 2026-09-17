from dpr.parsing.hcl import attributes, blocks, unquote

TF = """
terraform {
  required_version = ">= 1.5"
}

resource "azurerm_linux_web_app" "api" {
  name = "${var.project}-api-${var.env == "prod" ? "p" : "d"}"
  site_config {
    https_only = false
  }
  app_settings = {
    URL = "https://${azurerm_static_web_app.web.default_host_name}"
  }
  https_only = true # comment with a } brace
}

# resource "commented" "out" {
resource "azurerm_postgresql_flexible_server_firewall_rule" "azure" {
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}
"""


def test_blocks_labels_and_lines():
    found = blocks(TF)
    assert [(b.kind, b.labels, b.line) for b in found] == [
        ("terraform", (), 2),
        ("resource", ("azurerm_linux_web_app", "api"), 6),
        ("resource", ("azurerm_postgresql_flexible_server_firewall_rule", "azure"), 18),
    ]


def test_top_level_attributes_only():
    web = blocks(TF)[1]
    attrs = attributes(web)
    assert attrs["https_only"] == ("true", 14)
    assert "URL" not in attrs
    assert unquote(attrs["name"][0]).startswith("${var.project}")
    rule = attributes(blocks(TF)[2])
    assert (unquote(rule["start_ip_address"][0]), rule["end_ip_address"][1]) == ("0.0.0.0", 20)
