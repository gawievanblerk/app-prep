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


BLOCK_COMMENT_TF = """
/*
resource "azurerm_mssql_firewall_rule" "x" {
  start_ip_address = "0.0.0.0"
}
*/
resource "azurerm_mssql_firewall_rule" "y" {
  start_ip_address = "0.0.0.0"
}
"""


def test_block_comment_is_not_a_block():
    found = blocks(BLOCK_COMMENT_TF)
    assert [b.labels for b in found] == [("azurerm_mssql_firewall_rule", "y")]


BLOCK_COMMENT_BRACE_TF = """
resource "azurerm_linux_web_app" "api" {
  /* not enabled yet } */
  https_only = true
}
"""


def test_block_comment_brace_does_not_close_block():
    [block] = blocks(BLOCK_COMMENT_BRACE_TF)
    attrs = attributes(block)
    assert attrs["https_only"][0] == "true"


HEREDOC_TF = """
resource "aws_instance" "web" {
  user_data = <<-EOF
    echo start {
  EOF
}

resource "azurerm_linux_web_app" "api" {
  https_only = true
}
"""


def test_heredoc_does_not_swallow_next_resource():
    found = blocks(HEREDOC_TF)
    assert [b.labels for b in found] == [
        ("aws_instance", "web"),
        ("azurerm_linux_web_app", "api"),
    ]


COMMENT_AND_HASH_TF = """
resource "azurerm_linux_web_app" "api" {
  https_only = true // enabled for prod
  name       = "Allow#Tag"
}
"""


def test_attributes_strip_line_comment_and_keep_hash_in_string():
    [block] = blocks(COMMENT_AND_HASH_TF)
    attrs = attributes(block)
    assert attrs["https_only"][0] == "true"
    assert attrs["name"][0] == '"Allow#Tag"'
