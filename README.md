# Deployment Guide

## Quick Deploy Commands

### Deploy Latest Version (Recommended - GitHub Releases)

```bash
# Install latest release (no CDN caching issues)
fetch -o - https://github.com/kiennt048/net-shim/releases/latest/download/install.sh | sh
```

This downloads from GitHub Releases, which doesn't have CDN caching issues.

---

### Deploy Specific Version

```bash
# Deploy v1.7.1.28
fetch -o - https://github.com/kiennt048/net-shim/releases/download/v1.7.1.28/install.sh | sh

# Deploy v1.7.1.27
fetch -o - https://github.com/kiennt048/net-shim/releases/download/v1.7.1.27/install.sh | sh

# Deploy any version - replace with your tag
fetch -o - https://github.com/kiennt048/net-shim/releases/download/v1.7.1.XX/install.sh | sh
```
