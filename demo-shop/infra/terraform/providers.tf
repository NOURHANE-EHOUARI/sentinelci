# INTENTIONALLY VULNERABLE benchmark file (GT-SECRET-003): a cloud credential hard-coded in Terraform.
# FAKE key: "FAKEDEMOSENTINEL" is not a real AWS key id. Scanned only: never `terraform apply` this directory.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region     = "eu-west-3"
  access_key = "AKIAFAKEDEMOSENTINEL"
  secret_key = "FAKEsentinelDemoSecretKey/doNotUse+0123456789ab"
}
