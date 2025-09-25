# SecBot
A Slack bot to assist with day to day activities of a security engineer.
Powered by OpenAI API, Slack and few other open integrations like NIST CVE DB

## Features:
* It will ping you on slack when certain keywords are mentioned (configurable keywords). This will be helpful for cases where threat intel feeds are pumped into a slack channel
* Interact with ChatGPT right from slack.
* Search for CVE details using NIST database.
* Search for package vulnerabilities.

## Setup and Installation

### Prerequisites
- Python 3.8+
- Slack workspace with admin access
- OpenAI API account
- ngrok or similar tunneling tool for development

### Slack App Setup
1. Go to https://api.slack.com/apps and create a new app
2. Add bot permissions (chat:write, etc.)
3. Install the app to your workspace
4. Note down the Bot User OAuth Token and Signing Secret

### Environment Variables
Set the following environment variables securely (do NOT hardcode them in code):

```bash
export SLACK_BOT_TOKEN="xoxb-your-actual-bot-token"
export SLACK_SIGNING_SECRET="your-actual-signing-secret"
export OPENAI_API_KEY="sk-your-actual-openai-key"
export PORT=3000  # Optional, defaults to 3000
```

### Installation
1. Clone this repository
2. Create a virtual environment: `python3 -m venv venv`
3. Activate it: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Run the bot: `./run.sh` or `python3 app.py`

### Configuration
Edit `config.json` to customize:
- Keywords to monitor in Slack messages
- API timeouts and limits
- OpenAI model settings

## Usage
- Mention the bot with `@SecBot <message>` to chat with GPT
- Use `@SecBot cve_search CVE-2021-44228` to get CVE details
- Use `@SecBot package_search <package-name>` to search for vulnerabilities

## Security Warnings
- **Never commit API keys or secrets to version control**
- Use environment variables for all sensitive data
- Regularly rotate API keys
- Monitor API usage to avoid unexpected charges
- The bot uses OpenAI moderation, but additional safeguards may be needed for production use

## Built with:
* Slack Bolt SDK for Python
* OpenAI lib for python
* NIST NVD API
