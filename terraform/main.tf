# =============================================================================
# Root Terraform Configuration - OCI GitHub Actions Runners
# =============================================================================

module "gh_runners" {
  source = "./modules/oci-gh-runner"

  compartment_id             = var.compartment_id
  subnet_id                  = var.subnet_id
  availability_domain        = var.availability_domain
  ssh_public_key             = var.ssh_public_key
  network_security_group_ids = var.network_security_group_ids
  run_id                     = var.run_id
  github_pat                 = var.github_pat
  github_repo_url            = var.github_repo_url
  runners                    = var.runners
}

# =============================================================================
# Outputs
# =============================================================================

output "runner_public_ips" {
  description = "Map of runner key to public IP address"
  value       = module.gh_runners.runner_public_ips
}

output "runner_private_ips" {
  description = "Map of runner key to private IP address"
  value       = module.gh_runners.runner_private_ips
}

output "runner_instance_ids" {
  description = "List of all runner instance OCIDs"
  value       = module.gh_runners.runner_instance_ids
}

output "runner_instances" {
  description = "Map of created runner instances with their details"
  value       = module.gh_runners.runner_instances
}
