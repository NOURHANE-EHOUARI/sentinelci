# INTENTIONALLY VULNERABLE (GT-IAC-004): the CI role may do anything on any resource.
resource "aws_iam_policy" "ci_deploy" {
  name = "demo-shop-ci-deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
