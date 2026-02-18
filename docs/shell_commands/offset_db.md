# Offset Database Summary

## Concept
Map **Build-ID** → `{"package_nvr":"bash-5.1.8-9.el9","distro_family":"el9","build_ids":["aaa111...","bbb222...","ccc333..."],"offsets":{"readline":"0x000df690","execute_command":"0x0004dba0"}}` for each bash binary.
Build-ID is a unique hash embedded in every ELF binary.

## Script Purpose
1. Download bash-debuginfo packages from distro repos
2. Extract `readline` and `execute_command` offsets using `nm` or `objdump`
3. Store in DB keyed by Build-ID

## Distro URLs
| Distro | URL | Notes |
|--------|-----|-------|
| Ubuntu | `http://ddebs.ubuntu.com/pool/main/b/bash/` | All versions archived |
| AlmaLinux | `https://vault.almalinux.org/9/BaseOS/debug/x86_64/Packages/` | Full archive |
| Rocky | `https://download.rockylinux.org/vault/rocky/9.0/BaseOS/x86_64/debug/tree/Packages/b/` | Full archive |
| CentOS Stream | `kojihub.stream.centos.org` | **Latest only, no history** |

## BaseOS vs AppStream
- **BaseOS**: Core system packages including bash - **use this**
- **AppStream/others**: Application packages, modules - bash not here

## RHEL & Missing Packages
- RHEL has no public mirrors; use **AlmaLinux** as proxy (same NVR, different Build-ID). We need to test this
- Match by **NVR** (Name-Version-Release): `bash-5.1.8-6.el9_1` not Build-ID
- CentOS Stream only keeps latest; use **Koji** (`kojihub.stream.centos.org`) for older builds

## Build the DB
Write a script that scrapes all the distro packages.
Download all the symbols of all the bash/others builds ever made of that distro.
Use `nm` to get offset of the target files.
Populate the DB with this script

