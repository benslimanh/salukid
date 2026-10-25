/*
 * salukid on GKE Autopilot via Terraform.
 *
 *   - Enables GKE Autopilot (hardened by default: Workload Identity,
 *     shielded nodes, secure boot, private nodes optional)
 *   - Deploys salukid via the Helm chart in ../helm/salukid
 *   - Exposes via a regional L7 HTTPS LB + managed certificate
 *
 * This is a minimal, opinionated example; adapt to your project/host.
 */

terraform {
  required_version = ">= 1.5"
  required_providers {
    google   = { source = "hashicorp/google";   version = ">= 5.0" }
    kubernetes = { source = "hashicorp/kubernetes"; version = ">= 2.23" }
    helm     = { source = "hashicorp/helm";     version = ">= 2.11" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

/* ---------- GKE Autopilot ---------- */

resource "google_container_cluster" "salukid" {
  name             = "salukid"
  location         = var.region
  enable_autopilot = true
  release_channel  { channel = "REGULAR" }
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
  private_cluster_config {
    enable_private_nodes = false
    master_ipv4_cidr_block = "172.16.0.0/28"
  }
  ip_allocation_policy { cluster_secondary_range_name = "" }
}

data "google_client_config" "default" {}

/* ---------- K8s / Helm provider bootstrapping ---------- */

provider "kubernetes" {
  host  = "https://${google_container_cluster.salukid.endpoint}"
  token = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(
    google_container_cluster.salukid.master_auth[0].cluster_ca_certificate
  )
}

provider "helm" {
  kubernetes {
    host  = "https://${google_container_cluster.salukid.endpoint}"
    token = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(
      google_container_cluster.salukid.master_auth[0].cluster_ca_certificate
    )
  }
}

/* ---------- Namespace + secret (TLS) ---------- */

resource "kubernetes_namespace" "salukid" {
  metadata { name = "salukid" }
}

resource "kubernetes_secret" "tls" {
  metadata { name = "salukid-tls"; namespace = kubernetes_namespace.salukid.id }
  type = "kubernetes.io/tls"
  data = {
    "tls.crt" = filebase64(var.tls_cert_path)
    "tls.key" = filebase64(var.tls_key_path)
  }
}

/* ---------- salukid Helm release ---------- */

resource "helm_release" "salukid" {
  name       = "salukid"
  namespace  = kubernetes_namespace.salukid.id
  chart      = "${path.module}/../helm/salukid"
  depends_on = [kubernetes_secret.tls]
  values = [yamlencode({
    replicaCount = 3
    tls = { secretName = "salukid-tls" }
    resources = {
      requests = { cpu = "50m",  memory = "64Mi"  }
      limits   = { cpu = "500m", memory = "256Mi" }
    }
    networkPolicy = { enabled = true }
  })]
}
