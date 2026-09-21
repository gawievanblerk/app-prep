resource "aws_db_instance" "main" {
  identifier          = "shop"
  engine              = "postgres"
  publicly_accessible = true
}
