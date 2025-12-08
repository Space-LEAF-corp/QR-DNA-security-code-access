terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# DynamoDB table for key registry
resource "aws_dynamodb_table" "key_registry" {
  name           = var.table_name
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "keyId"
  
  attribute {
    name = "keyId"
    type = "S"
  }
  
  attribute {
    name = "createdAt"
    type = "N"
  }
  
  global_secondary_index {
    name            = "CreatedAtIndex"
    hash_key        = "keyId"
    range_key       = "createdAt"
    projection_type = "ALL"
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  server_side_encryption {
    enabled = true
  }
  
  tags = {
    Name        = "Fox QPPI Key Registry"
    Application = "fox-qppi"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# IAM role for key registry access
resource "aws_iam_role" "key_registry_role" {
  name = "${var.table_name}-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name        = "Fox QPPI Key Registry Role"
    Application = "fox-qppi"
    Environment = var.environment
  }
}

# IAM policy for DynamoDB access
resource "aws_iam_role_policy" "key_registry_policy" {
  name = "${var.table_name}-policy"
  role = aws_iam_role.key_registry_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.key_registry.arn,
          "${aws_dynamodb_table.key_registry.arn}/index/*"
        ]
      }
    ]
  })
}

# KMS key for encryption at rest
resource "aws_kms_key" "key_registry_kms" {
  description             = "KMS key for Fox QPPI Key Registry"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name        = "Fox QPPI Key Registry KMS"
    Application = "fox-qppi"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "key_registry_kms_alias" {
  name          = "alias/${var.table_name}-kms"
  target_key_id = aws_kms_key.key_registry_kms.key_id
}

# CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "read_throttle" {
  alarm_name          = "${var.table_name}-read-throttle"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "DynamoDB read throttling detected"
  
  dimensions = {
    TableName = aws_dynamodb_table.key_registry.name
  }
  
  tags = {
    Application = "fox-qppi"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "write_throttle" {
  alarm_name          = "${var.table_name}-write-throttle"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "DynamoDB write throttling detected"
  
  dimensions = {
    TableName = aws_dynamodb_table.key_registry.name
  }
  
  tags = {
    Application = "fox-qppi"
    Environment = var.environment
  }
}
