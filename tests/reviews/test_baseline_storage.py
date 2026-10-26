from tests.reviews.helpers import findings_for, write

RULE = "BASE-STORAGE-UNENCRYPTED"

TERRAFORM = """
resource "aws_db_instance" "off" {
  engine            = "postgres"
  storage_encrypted = false
}
resource "aws_db_instance" "unset" {
  engine = "postgres"
}
resource "aws_db_instance" "on" {
  storage_encrypted = true
}
resource "aws_db_instance" "replica" {
  replicate_source_db = aws_db_instance.on.identifier
}
resource "aws_rds_cluster" "serverless" {
  engine_mode = "serverless"
}
resource "aws_ebs_volume" "unset" {
  size = 10
}
resource "aws_ebs_volume" "off" {
  encrypted = false
}
resource "aws_efs_file_system" "files" {
  creation_token = "files"
}
resource "aws_elasticache_replication_group" "cache" {
  at_rest_encryption_enabled = false
}
"""


def test_unencrypted_storage(tmp_path):
    write(tmp_path, "infra/main.tf", TERRAFORM)
    found = {(f.locations[0].line, f.tag.value) for f in findings_for(tmp_path, "baseline", RULE)}
    assert found == {
        (4, "CONFIRMED"),  # aws_db_instance.off
        (6, "INFERRED"),  # aws_db_instance.unset: the provider default is off
        (22, "CONFIRMED"),  # aws_ebs_volume.off
        (24, "INFERRED"),  # aws_efs_file_system.files
        (28, "CONFIRMED"),  # aws_elasticache_replication_group.cache
    }


def test_detail_names_the_resource(tmp_path):
    write(tmp_path, "infra/main.tf", TERRAFORM)
    details = [f.detail for f in findings_for(tmp_path, "baseline", RULE)]
    assert any(d.startswith("aws_db_instance off sets storage_encrypted = false.") for d in details)
