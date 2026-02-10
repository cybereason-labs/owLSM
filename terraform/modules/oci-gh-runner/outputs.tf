# =============================================================================
# OCI GitHub Actions Runner Module - Outputs
# =============================================================================

output "runner_instances" {
  description = "Map of created runner instances with their details"
  value = {
    for key, instance in oci_core_instance.gh_runner : key => {
      id           = instance.id
      display_name = instance.display_name
      state        = instance.state
      public_ip    = instance.public_ip
      private_ip   = instance.private_ip
      shape        = instance.shape
      image_id     = var.runners[key].image_id
    }
  }
}

output "runner_instance_ids" {
  description = "List of all runner instance OCIDs"
  value       = [for instance in oci_core_instance.gh_runner : instance.id]
}

output "runner_public_ips" {
  description = "Map of runner key to public IP address"
  value       = { for key, instance in oci_core_instance.gh_runner : key => instance.public_ip }
}

output "runner_private_ips" {
  description = "Map of runner key to private IP address"
  value       = { for key, instance in oci_core_instance.gh_runner : key => instance.private_ip }
}
