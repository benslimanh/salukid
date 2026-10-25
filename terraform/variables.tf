variable "project_id" {
  description = "GCP project id."
  type        = string
}

variable "region" {
  description = "GCP region (Autopilot regional)."
  type        = string
  default     = "europe-west1"
}

variable "tls_cert_path" {
  description = "Path to TLS certificate PEM."
  type        = string
  default     = "../certs/cert.pem"
}

variable "tls_key_path" {
  description = "Path to TLS private key PEM."
  type        = string
  default     = "../certs/key.pem"
}
