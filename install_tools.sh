#!/bin/bash

# Install Go tools
echo "Installing Go tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v3/...@master
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest

# Install jq if not already installed
if ! command -v jq &> /dev/null; then
    echo "Installing jq..."
    brew install jq
fi

# Install porch-pirate
pipx install porch-pirate

echo "Installation complete!"
echo "Please add $HOME/go/bin to your PATH if not already added."
