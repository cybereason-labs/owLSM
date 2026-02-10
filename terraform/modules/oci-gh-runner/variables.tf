# =============================================================================
# OCI GitHub Actions Runner - Variables
# =============================================================================

# --- OCI Infrastructure ---

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
  description = "Unique identifier for the workflow run (e.g., GitHub Actions run_id). Appended to runner display names to ensure uniqueness across parallel runs."
  type        = string
}

# --- Runner Definitions ---

variable "runners" {
  description = <<-EOT
    Map of runner configurations. Each entry creates one OCI instance registered
    as a GitHub Actions runner.

    Example:
      runners = {
        ubuntu-22 = {
          image_id       = "ocid1.image.oc1..."
          display_name   = "runner-ubuntu-22"
          shape          = "VM.Standard.E4.Flex"
          ocpus          = 2
          memory_in_gbs  = 16
          boot_volume_gb = 100
          runner_labels  = ["self-hosted", "linux", "x64", "ubuntu-22", "OCI"]
        }
      }
  EOT
  type = map(object({
    image_id       = string
    display_name   = string
    shape          = optional(string, "VM.Standard.E4.Flex")
    ocpus          = optional(number, 2)
    memory_in_gbs  = optional(number, 16)
    boot_volume_gb = optional(number, 100)
    runner_labels  = optional(list(string), ["self-hosted", "linux", "x64", "OCI"])
  }))

  validation {
    condition     = length(var.runners) > 0
    error_message = "At least one runner must be defined."
  }
}

# --- GitHub Runner Registration ---

variable "github_pat" {
  description = "GitHub Personal Access Token with 'repo' scope for runner registration"
  type        = string
  sensitive   = true
}

variable "github_repo_url" {
  description = "GitHub repository URL (e.g., https://github.com/owner/repo)"
  type        = string

  validation {
    condition     = can(regex("^https://github\\.com/.+/.+$", var.github_repo_url))
    error_message = "github_repo_url must be a valid GitHub repository URL (https://github.com/owner/repo)."
  }
}

variable "runner_version" {
  description = "GitHub Actions runner version to install"
  type        = string
  default     = "2.321.0"
}

variable "runner_group" {
  description = "GitHub runner group name"
  type        = string
  default     = "Default"
}

# --- Instance Defaults ---

variable "instance_tags" {
  description = "Freeform tags to apply to all runner instances"
  type        = map(string)
  default = {
    managed-by = "terraform"
    purpose    = "github-actions-runner"
  }
}

variable "runner_user" {
  description = "OS user to run the GitHub Actions runner service"
  type        = string
  default     = "ghrunner"
}
