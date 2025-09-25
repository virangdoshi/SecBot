#!/bin/bash

# SecBot Development Environment Setup
# This script creates a virtual environment and installs all dependencies

set -e  # Exit on any error

echo "🐍 Setting up SecBot development environment..."

# Check if Python 3.8+ is available
if ! python3 --version >/dev/null 2>&1; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python $PYTHON_VERSION detected. SecBot requires Python $REQUIRED_VERSION or higher."
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"

# Create virtual environment if it doesn't exist
if [ -d "secbot_env" ]; then
    echo "⚠️  Virtual environment 'secbot_env' already exists"
    read -p "Do you want to recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🗑️  Removing existing virtual environment..."
        rm -rf secbot_env
    else
        echo "ℹ️  Using existing virtual environment"
        exit 0
    fi
fi

echo "🏗️  Creating virtual environment..."
python3 -m venv secbot_env

echo "📦 Installing dependencies..."
source secbot_env/bin/activate
pip install --upgrade pip
pip install -r requirements-lock.txt

echo ""
echo "🎉 Setup complete!"
echo ""
echo "🚀 To run SecBot:"
echo "   1. Set environment variables:"
echo "      export SLACK_BOT_TOKEN='your-slack-bot-token'"
echo "      export SLACK_SIGNING_SECRET='your-slack-signing-secret'"
echo "      export OPENAI_API_KEY='your-openai-api-key'"
echo ""
echo "   2. Run the application:"
echo "      ./run.sh"
echo ""
echo "🧪 To run tests:"
echo "   source secbot_env/bin/activate"
echo "   ./run_tests.sh"
