# =============================================================================
# Root Terraform Variables - OCI GitHub Actions Runners
# =============================================================================

variable "compartment_id" {
  description = "OCI compartment OCID where instances will be created"
  type        = string
}

variable "subnet_id" {
  description = "OCI subnet OCID for the runner instances"
  type        = string
}

variable "availability_domain" {
  description = "OCI availability domain for the instances"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key for instance access"
  type        = string
}

variable "network_security_group_ids" {
  description = "List of OCI Network Security Group OCIDs to attach to runner instances"
  type        = list(string)
  default     = []
}

variable "run_id" {
  description = "Unique identifier for the workflow run, appended to runner names for parallel run isolation"
  type        = string
}

variable "github_pat" {
  description = "GitHub Personal Access Token with 'repo' scope for runner registration"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "OCI region identifier (e.g., us-ashburn-1)"
  type        = string
}

variable "github_repo_url" {
  description = "GitHub repository URL (e.g., https://github.com/owner/repo)"
  type        = string
}

variable "runners" {
  description = "Map of runner configurations. Each entry creates one OCI instance."
  type = map(object({
    image_id       = string
    display_name   = string
    shape          = optional(string, "VM.Standard.E4.Flex")
    ocpus          = optional(number, 2)
    memory_in_gbs  = optional(number, 16)
    boot_volume_gb = optional(number, 100)
    runner_labels  = optional(list(string), ["self-hosted", "linux", "x64", "OCI"])
  }))
}
