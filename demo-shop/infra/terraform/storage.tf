# INTENTIONALLY VULNERABLE (GT-IAC-001): the product-images bucket is public, unencrypted and not logged.
resource "aws_s3_bucket" "product_images" {
  bucket = "demo-shop-product-images"
}

resource "aws_s3_bucket_acl" "product_images" {
  bucket = aws_s3_bucket.product_images.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "product_images" {
  bucket                  = aws_s3_bucket.product_images.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
