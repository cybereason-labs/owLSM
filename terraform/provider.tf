# =============================================================================
# OCI Provider Configuration
# Uses local OCI config file at ~/.oci/config (pre-baked in runner images).
# The config and private API key are located at /home/ghrunner/.oci/
# =============================================================================

provider "oci" {
  config_file_profile = "DEFAULT"
  region              = var.region
}
