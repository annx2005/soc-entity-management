variable "project_id" {
  description = "Google Cloud project ID that will host the demo GKE deployment."
  type        = string
}

variable "region" {
  description = "Google Cloud region for regional resources."
  type        = string
  default     = "asia-southeast1"
}

variable "zone" {
  description = "Google Cloud zone for the zonal GKE cluster."
  type        = string
  default     = "asia-southeast1-a"
}

variable "name_prefix" {
  description = "Prefix used for GCP resource names."
  type        = string
  default     = "soc-entity-management"
}

variable "gke_cluster_name" {
  description = "GKE cluster name."
  type        = string
  default     = "soc-entity-management"
}

variable "k8s_namespace" {
  description = "Kubernetes namespace used by the Helm release."
  type        = string
  default     = "soc-entity-management"
}

variable "artifact_registry_repository" {
  description = "Artifact Registry Docker repository name."
  type        = string
  default     = "soc-entity-management"
}

variable "ingress_static_ip_name" {
  description = "Name of the global static IP used by the GKE HTTP Ingress."
  type        = string
  default     = "soc-entity-management-http-ip"
}

variable "github_repository" {
  description = "GitHub repository allowed to deploy, in owner/repo format."
  type        = string
  default     = "annx2005/soc-entity-management"
}

variable "github_main_branch" {
  description = "Branch allowed to deploy through GitHub Actions OIDC."
  type        = string
  default     = "main"
}

variable "node_machine_type" {
  description = "Machine type for the default GKE node pool."
  type        = string
  default     = "e2-standard-4"
}

variable "node_disk_size_gb" {
  description = "Boot disk size for GKE nodes."
  type        = number
  default     = 50
}

variable "node_min_count" {
  description = "Minimum node count for the GKE node pool."
  type        = number
  default     = 1
}

variable "node_max_count" {
  description = "Maximum node count for the GKE node pool."
  type        = number
  default     = 3
}
