resource "aws_s3_bucket" "insecure_demo" {
  bucket = "example-insecure-demo-do-not-deploy"
}
resource "aws_s3_bucket_public_access_block" "insecure_demo" {
  bucket                  = aws_s3_bucket.insecure_demo.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
