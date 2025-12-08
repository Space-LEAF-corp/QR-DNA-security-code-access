output "table_name" {
  description = "Name of the DynamoDB table"
  value       = aws_dynamodb_table.key_registry.name
}

output "table_arn" {
  description = "ARN of the DynamoDB table"
  value       = aws_dynamodb_table.key_registry.arn
}

output "role_arn" {
  description = "ARN of the IAM role"
  value       = aws_iam_role.key_registry_role.arn
}

output "kms_key_id" {
  description = "ID of the KMS key"
  value       = aws_kms_key.key_registry_kms.key_id
}

output "kms_key_arn" {
  description = "ARN of the KMS key"
  value       = aws_kms_key.key_registry_kms.arn
}
