#!/bin/bash
# Ensure environment variables are set
if [ -z "$SLACK_BOT_TOKEN" ]; then
    echo "Error: SLACK_BOT_TOKEN environment variable is not set."
    exit 1
fi

if [ -z "$SLACK_SIGNING_SECRET" ]; then
    echo "Error: SLACK_SIGNING_SECRET environment variable is not set."
    exit 1
fi

if [ -z "$OPENAI_API_KEY" ]; then
    echo "Error: OPENAI_API_KEY environment variable is not set."
    exit 1
fi

# Install dependencies (consider using virtual environment)
pip3 install -r requirements.txt

# Run the application
python3 app.py
