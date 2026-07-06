# GKE Bootstrap Terraform

This Terraform module bootstraps the Google Cloud resources required by the
GitHub Actions Helm deployment.

State intentionally uses the local backend. Run Terraform from a trusted local
machine and do not run `terraform apply` from GitHub Actions unless the backend
is migrated to shared remote state.

## First Run

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your project_id and repository if needed.
terraform init
terraform apply
terraform output github_actions_variables
```

Copy the `github_actions_variables` output into GitHub repository Variables and
set the required repository Secrets:

- `JWT_SECRET_KEY`
- `POSTGRES_PASSWORD`
- `NEO4J_PASSWORD`

GitHub Actions uses Workload Identity Federation/OIDC and does not need a
long-lived Google service account key.
