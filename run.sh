#!/bin/bash

# SecBot Application Runner
# This script sets up and runs the SecBot application using a virtual environment

set -e  # Exit on any error

# Check if virtual environment exists
if [ ! -d "secbot_env" ]; then
    echo "❌ Virtual environment 'secbot_env' not found!"
    echo "🔧 Run setup script first: ./setup.sh"
    exit 1
fi

# Ensure environment variables are set
if [ -z "$SLACK_BOT_TOKEN" ]; then
    echo "❌ Error: SLACK_BOT_TOKEN environment variable is not set."
    echo "💡 Set it with: export SLACK_BOT_TOKEN='your-token-here'"
    exit 1
fi

if [ -z "$SLACK_SIGNING_SECRET" ]; then
    echo "❌ Error: SLACK_SIGNING_SECRET environment variable is not set."
    echo "💡 Set it with: export SLACK_SIGNING_SECRET='your-secret-here'"
    exit 1
fi

if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OPENAI_API_KEY environment variable is not set."
    echo "💡 Set it with: export OPENAI_API_KEY='your-key-here'"
    exit 1
fi

echo "🚀 Starting SecBot..."

# Activate virtual environment and run the application
source secbot_env/bin/activate
python app.py
