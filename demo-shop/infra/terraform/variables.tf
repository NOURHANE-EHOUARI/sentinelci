# Clean control GT-CLEAN-002: secrets are variables marked sensitive, supplied at plan time, never in code.
variable "db_password" {
  type        = string
  sensitive   = true
  description = "Orders database password (from the CI secret store)."
}
