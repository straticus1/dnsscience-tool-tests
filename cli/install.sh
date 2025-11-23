#!/bin/bash
# DNSScience CLI Installation Script
# Supports: Linux, macOS, Windows (WSL)

set -e

echo "================================================"
echo "DNSScience CLI Installation"
echo "================================================"
echo ""

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    echo "Warning: Unknown OS type: $OSTYPE"
fi

echo "Detected OS: $OS"
echo ""

# Check Python version
echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    echo "Please install Python 3.7 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "Found Python: $PYTHON_VERSION"

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 is not installed"
    echo "Please install pip3"
    exit 1
fi

echo "Found pip3: $(pip3 --version)"
echo ""

# Installation method selection
echo "Select installation method:"
echo "1) Install globally (requires sudo/admin)"
echo "2) Install for current user only"
echo "3) Install in virtual environment (recommended for development)"
echo ""
read -p "Enter choice [1-3]: " INSTALL_METHOD

case $INSTALL_METHOD in
    1)
        echo ""
        echo "Installing globally..."
        if [[ "$OS" == "linux" ]] || [[ "$OS" == "macos" ]]; then
            sudo pip3 install -r requirements.txt
            sudo pip3 install -e .
        else
            pip3 install -r requirements.txt
            pip3 install -e .
        fi
        ;;
    2)
        echo ""
        echo "Installing for current user..."
        pip3 install --user -r requirements.txt
        pip3 install --user -e .

        # Add to PATH if not already there
        if [[ "$OS" == "linux" ]] || [[ "$OS" == "macos" ]]; then
            USER_BIN="$HOME/.local/bin"
            if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
                echo ""
                echo "Warning: $USER_BIN is not in your PATH"
                echo "Add this to your ~/.bashrc or ~/.zshrc:"
                echo "export PATH=\"\$HOME/.local/bin:\$PATH\""
            fi
        fi
        ;;
    3)
        echo ""
        echo "Creating virtual environment..."
        python3 -m venv venv
        source venv/bin/activate

        echo "Installing in virtual environment..."
        pip install -r requirements.txt
        pip install -e .

        echo ""
        echo "Virtual environment created at: ./venv"
        echo "Activate with: source venv/bin/activate"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "================================================"
echo "Installation Complete!"
echo "================================================"
echo ""

# Test installation
echo "Testing installation..."
if command -v dnsscience &> /dev/null; then
    echo "✓ dnsscience command is available"
    dnsscience --version
    echo ""
    echo "Run 'dnsscience --help' to see available commands"
else
    echo "✗ dnsscience command not found in PATH"
    echo ""
    if [[ $INSTALL_METHOD -eq 2 ]]; then
        echo "Make sure ~/.local/bin is in your PATH"
    elif [[ $INSTALL_METHOD -eq 3 ]]; then
        echo "Activate the virtual environment: source venv/bin/activate"
    fi
fi

echo ""
echo "Quick Start:"
echo "  dnsscience autodetect              # Detect your DNS"
echo "  dnsscience email example.com       # Email security check"
echo "  dnsscience ssl example.com         # SSL certificate check"
echo "  dnsscience trace example.com       # Traceroute"
echo ""
echo "For full documentation, see README.md"
echo ""
