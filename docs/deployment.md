# Deployment Guide

## Quick Deploy Commands

### Deploy Latest Version (kientest branch)

```bash
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/kientest/install.sh | sh
```

This installs the latest build from the `kientest` branch.

---

### Deploy Specific Version (by tag)

```bash
# Deploy v1.7.1.26
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/v1.7.1.26/install.sh | sh

# Deploy v1.7.1.25
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/v1.7.1.25/install.sh | sh

# Deploy any version - replace with your tag
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/v1.7.1.XX/install.sh | sh
```

This allows you to install a specific version or rollback to a previous version.

---

## Version Management

### View Available Versions

Check all available tags/versions:
- GitHub Tags: https://github.com/kiennt048/net-shim/tags
- GitHub Releases: https://github.com/kiennt048/net-shim/releases

### Version Format

Tags follow the format: `vMAJOR.MINOR.PATCH.BUILD`

Example: `v1.7.1.26`
- Major: 1
- Minor: 7
- Patch: 1
- Build: 26 (auto-incremented on each build)

---

## Deployment Workflow

### For Developers

1. **Build and deploy**:
   ```bash
   make build    # Builds binary, updates SHA256
   make deploy   # Commits, tags, and pushes to GitHub
   ```

2. **Auto-deploy** (optional):
   - Uncomment line 51 in Makefile: `@$(MAKE) deploy`
   - Now `make build` will automatically deploy

### For System Administrators

1. **Deploy to pfSense box**:
   ```bash
   # SSH into pfSense
   ssh admin@your-pfsense-ip
   
   # Run install command
   fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/kientest/install.sh | sh
   ```

2. **Verify installation**:
   ```bash
   /usr/local/bin/net-shim --version
   ```

3. **Rollback if needed**:
   ```bash
   # Install previous version
   fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/v1.7.1.25/install.sh | sh
   ```

---

## Build Information

Each tag contains build metadata:
- **Version**: Full version string (e.g., `v1.7.1.26_20260130_0920`)
- **SHA256**: Binary checksum for verification
- **Branch**: Source branch (`kientest`)
- **Build Time**: Timestamp of build

View tag details:
```bash
git show v1.7.1.26
```

---

## Troubleshooting

### Installation fails with SHA256 mismatch

The `install.sh` script verifies the binary SHA256. If it fails:
1. Check if the binary was corrupted during download
2. Verify you're using the correct tag/branch
3. Re-run the install command

### Cannot fetch from GitHub

Check network connectivity:
```bash
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/kientest/install.sh
```

If this fails, check:
- pfSense has internet access
- DNS is working
- GitHub is accessible

### Wrong version installed

Check installed version:
```bash
/usr/local/bin/net-shim --version
```

Reinstall specific version:
```bash
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/v1.7.1.XX/install.sh | sh
```

---

## Best Practices

1. **Test before deploying to production**:
   - Deploy to a test pfSense box first
   - Verify functionality
   - Then deploy to production boxes

2. **Keep track of versions**:
   - Note which version is running on each box
   - Document any issues with specific versions

3. **Use tags for production**:
   - Use `kientest` branch for testing
   - Use specific tags for production deployments
   - This allows easy rollback if needed

4. **Backup before upgrading**:
   - pfSense config is backed up automatically
   - But consider manual backup for critical systems

---

## Repository Structure

- **Branch: `kientest`** - Latest builds, bleeding edge
- **Tags: `v1.7.1.XX`** - Stable releases, version-locked
- **Branch: `main`** - (if exists) Stable production branch

For automated deployments, use the `kientest` branch.
For production systems, use specific version tags.
