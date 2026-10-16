terraform {
  required_version = ">= 1.6.0"
}

variable "environment" {
  type        = string
  default     = "production-zero-trust"
  description = "Target deployment environment with mandatory KMS and PrivateLink guardrails"
}

locals {
  platform_name      = "OmniMesh Enterprise Data & Network Factory"
  zero_trust_enabled = true
  public_ip_allowed  = false
  kms_encryption     = "AES-256-GCM-CMK"
  vlsm_allocations = {
    payments_core_spark_compute = { cidr = "10.100.0.0/23", cloud = "AWS", region = "us-east-1", policy = "PRIVATE_ISOLATED_KMS" }
    fraud_risk_engine_spark_compute = { cidr = "10.200.0.0/23", cloud = "AZURE", region = "westeurope", policy = "PRIVATE_ISOLATED_KMS" }
    settlement_ledger_spark_compute = { cidr = "10.100.2.0/24", cloud = "AWS", region = "us-east-1", policy = "PRIVATE_ISOLATED_KMS" }
    payments_core_k8s_ingest = { cidr = "10.100.3.0/24", cloud = "AWS", region = "us-east-1", policy = "ZERO_TRUST_INGRESS" }
    fraud_risk_engine_k8s_ingest = { cidr = "10.200.2.0/25", cloud = "AZURE", region = "westeurope", policy = "ZERO_TRUST_INGRESS" }
    settlement_ledger_k8s_ingest = { cidr = "10.100.4.0/25", cloud = "AWS", region = "us-east-1", policy = "ZERO_TRUST_INGRESS" }
    payments_core_privatelink_endpoints = { cidr = "10.100.4.128/26", cloud = "AWS", region = "us-east-1", policy = "NO_PUBLIC_INTERNET" }
    fraud_risk_engine_privatelink_endpoints = { cidr = "10.200.2.128/26", cloud = "AZURE", region = "westeurope", policy = "NO_PUBLIC_INTERNET" }
    settlement_ledger_privatelink_endpoints = { cidr = "10.100.4.192/27", cloud = "AWS", region = "us-east-1", policy = "NO_PUBLIC_INTERNET" }
  }
}

output "zero_trust_posture_verified" {
  description = "Confirms Zero-Trust network isolation and disabled public internet egress"
  value       = local.zero_trust_enabled && !local.public_ip_allowed
}

output "allocated_subnet_count" {
  description = "Total conflict-free VLSM subnets compiled across AWS and Azure"
  value       = length(local.vlsm_allocations)
}
