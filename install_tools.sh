#!/bin/bash

set -e  # Exit on error

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if running as root/sudo
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root is not recommended. Some tools may not install properly.${NC}"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborting installation."
        exit 1
    fi
fi

# Detect OS and package manager
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    PKG_MANAGER="brew"
    PKG_INSTALL="install"
    PKG_UPDATE="update"
    PKG_UPGRADE="upgrade"
elif [[ -f /etc/debian_version ]]; then
    OS="debian"
    PKG_MANAGER="apt-get"
    PKG_INSTALL="install -y"
    PKG_UPDATE="update"
    PKG_UPGRADE="upgrade -y"
else
    echo -e "${RED}Error: Unsupported operating system. Only macOS and Debian/Ubuntu are supported.${NC}"
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install a package if not already installed
install_pkg() {
    local pkg=$1
    local name=${2:-$pkg}
    
    if ! command_exists "$pkg"; then
        echo -e "${GREEN}Installing $name...${NC}"
        if [ "$OS" = "macos" ]; then
            $PKG_MANAGER $PKG_INSTALL "$pkg"
        else
            sudo $PKG_MANAGER $PKG_UPDATE
            sudo $PKG_MANAGER $PKG_INSTALL "$pkg"
        fi
    else
        echo -e "${YELLOW}$name is already installed.${NC}"
    fi
}

# Update package lists
echo -e "\n${GREEN}Updating package lists...${NC}"
if [ "$OS" = "macos" ]; then
    $PKG_MANAGER $PKG_UPDATE
else
    sudo $PKG_MANAGER $PKG_UPDATE
fi

# Install prerequisites
install_pkg "git" "Git"
install_pkg "python3" "Python 3"
install_pkg "python3-pip" "Python pip"
install_pkg "jq" "jq"
install_pkg "go" "Go"

# Install Python packages
echo -e "\n${GREEN}Installing Python packages...${NC}"
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Install pipx for porch-pirate
if ! command_exists pipx; then
    echo -e "${GREEN}Installing pipx...${NC}"
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    export PATH="$PATH:$HOME/.local/bin"
fi

# Install porch-pirate
echo -e "\n${GREEN}Installing porch-pirate...${NC}"
pipx install porch-pirate

# Install Go tools
echo -e "\n${GREEN}Installing Go tools...${NC}"
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v3/...@master"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    echo -e "${GREEN}Installing/Updating $tool...${NC}"
    go install -v $tool
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install $tool${NC}"
        # Continue with next tool even if one fails
    fi
done

# Set up environment
echo -e "\n${GREEN}Setting up environment...${NC}"

# Add Go bin to PATH if not already in .bashrc or .zshrc
if ! grep -q "export PATH=\"\$PATH:$HOME/go/bin\"" ~/.bashrc 2>/dev/null; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
fi

if [ -f ~/.zshrc ] && ! grep -q "export PATH=\"\$PATH:$HOME/go/bin\"" ~/.zshrc; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc
fi

# Source the updated shell configuration
if [ -n "$BASH_VERSION" ]; then
    source ~/.bashrc
elif [ -n "$ZSH_VERSION" ]; then
    source ~/.zshrc
fi

echo -e "\n${GREEN}Installation complete!${NC}"
echo -e "${YELLOW}Please restart your terminal or run 'source ~/.bashrc' (or 'source ~/.zshrc') to update your PATH.${NC}"
echo -e "${YELLOW}You may need to log out and log back in for all changes to take effect.${NC}"
