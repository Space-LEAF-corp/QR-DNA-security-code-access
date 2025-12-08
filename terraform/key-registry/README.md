# Fox QPPI Key Registry Infrastructure

This Terraform module provisions the infrastructure for the Fox QPPI key registry on AWS.

## Resources Created

- **DynamoDB Table**: Key registry storage with pay-per-request billing
- **IAM Role & Policy**: Service access permissions
- **KMS Key**: Encryption at rest for DynamoDB
- **CloudWatch Alarms**: Monitoring for throttling events

## Usage

### Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform >= 1.0 installed

### Deployment

1. Initialize Terraform:
```bash
cd terraform/key-registry
terraform init
```

2. Review the plan:
```bash
terraform plan -var="environment=prod"
```

3. Apply the configuration:
```bash
terraform apply -var="environment=prod"
```

### Variables

- `aws_region`: AWS region (default: us-east-1)
- `table_name`: DynamoDB table name (default: fox-qppi-key-registry)
- `environment`: Environment name (default: dev)

### Outputs

- `table_name`: Name of the created DynamoDB table
- `table_arn`: ARN of the DynamoDB table
- `role_arn`: ARN of the IAM role
- `kms_key_id`: ID of the KMS key
- `kms_key_arn`: ARN of the KMS key

## Security Features

- Point-in-time recovery enabled
- Server-side encryption with KMS
- Automatic key rotation enabled
- CloudWatch alarms for monitoring
- Principle of least privilege IAM policies

## Cost Considerations

- DynamoDB uses PAY_PER_REQUEST billing mode
- No provisioned capacity charges
- Pay only for actual read/write requests
- Point-in-time recovery incurs additional costs

## Cleanup

To destroy the infrastructure:
```bash
terraform destroy -var="environment=prod"
```

**Warning**: This will delete all data in the key registry table!
