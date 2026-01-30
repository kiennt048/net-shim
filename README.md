# Install latest (kientest branch) - DEFAULT
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/kientest/install.sh | sh

# Install specific version tag
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/kientest/install.sh | sh -s v1.7.1.26

# Install from main branch
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/kientest/install.sh | sh -s main

# Install from any branch/tag
fetch -o - https://raw.githubusercontent.com/kiennt048/net-shim/kientest/install.sh | sh -s <version>
