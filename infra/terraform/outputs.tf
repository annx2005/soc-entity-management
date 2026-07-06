output "github_actions_variables" {
  description = "Copy these values into GitHub Actions repository variables."
  value = {
    GCP_PROJECT_ID         = var.project_id
    GKE_CLUSTER            = google_container_cluster.main.name
    GKE_LOCATION           = google_container_cluster.main.location
    GAR_LOCATION           = google_artifact_registry_repository.docker.location
    GAR_REPOSITORY         = google_artifact_registry_repository.docker.repository_id
    WIF_PROVIDER           = google_iam_workload_identity_pool_provider.github.name
    WIF_SERVICE_ACCOUNT    = google_service_account.github_deploy.email
    K8S_NAMESPACE          = var.k8s_namespace
    INGRESS_STATIC_IP_NAME = google_compute_global_address.ingress.name
  }
}

output "ingress_ip_address" {
  description = "Reserved global static IP address for the public HTTP Ingress."
  value       = google_compute_global_address.ingress.address
}

output "artifact_registry_image_prefix" {
  description = "Docker image prefix used by GitHub Actions and Helm."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.docker.repository_id}"
}
