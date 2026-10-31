# INTENTIONALLY VULNERABLE (GT-IAC-002): SSH open to the whole internet.
resource "aws_security_group" "shop_api" {
  name        = "demo-shop-api"
  description = "shop-api instances"

  ingress {
    description = "SSH for debugging"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
