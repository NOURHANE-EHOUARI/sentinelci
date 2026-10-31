# INTENTIONALLY VULNERABLE (GT-IAC-003): the orders database is reachable from the internet and not encrypted.
resource "aws_db_instance" "orders" {
  identifier          = "demo-shop-orders"
  engine              = "postgres"
  engine_version      = "16"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  username            = "shop"
  password            = var.db_password
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
