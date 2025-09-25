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
2. Run automated setup: `./setup.sh`
3. Set environment variables (see below)
4. Run the bot: `./run.sh`

The setup script will:
- Create a virtual environment (`secbot_env/`)
- Install all dependencies from the locked requirements
- Verify Python version compatibility

### Configuration
Edit `config.json` to customize:
- Keywords to monitor in Slack messages
- API timeouts and limits
- OpenAI model settings
- Security settings (message length limits, package name validation)
- Alert user ID for keyword notifications (replace `CHANGE_ME_TO_YOUR_SLACK_USER_ID` with your actual Slack user ID)

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

## Development

### Commit Signing
All commits to this repository should be signed with GPG keys for security verification:

```bash
# Configure git for signed commits
git config --global commit.gpgsign true
git config --global user.signingkey YOUR_GPG_KEY_ID

# Verify commits are signed
git log --show-signature
```

## Testing

This project includes comprehensive unit tests and automated quality checks.

### Running Tests Locally

1. **Automated test suite:**
   ```bash
   ./run_tests.sh
   ```
   This runs all tests with coverage, linting, type checking, and security scanning.

2. **Manual test execution:**
   ```bash
   # Activate virtual environment (created by setup.sh)
   source secbot_env/bin/activate
   
   # Set test environment variables
   export OPENAI_API_KEY="sk-test-key-for-testing-only"
   export SLACK_BOT_TOKEN="xoxb-test-token-for-testing-only"
   export SLACK_SIGNING_SECRET="test-signing-secret-for-testing-only"
   
   # Run tests
   pytest --cov=. --cov-report=term-missing --cov-report=html
   ```

3. **View coverage report:**
   Open `htmlcov/index.html` in your browser after running tests.

### Test Structure

- `test_utils.py` - Tests for CVE and package search functionality
- `test_handlers.py` - Tests for OpenAI message handling and moderation
- `test_app.py` - Tests for Slack bot event handlers and integration
- `pytest.ini` - Pytest configuration with coverage settings
- `run_tests.sh` - Comprehensive test runner script

### Continuous Integration

The project uses GitHub Actions to automatically run tests on every pull request:

- **Test Environment**: Python 3.12 (latest stable version)
- **Code Quality**: Includes linting (flake8), type checking (mypy), and security scanning (bandit)
- **Coverage**: Generates coverage reports and comments on PRs
- **Security**: Runs Trivy vulnerability scanner and dependency checks
- **Dependencies**: Checks for known vulnerabilities with Safety and pip-audit

## Built with:
* Slack Bolt SDK for Python
* OpenAI lib for python
* NIST NVD API
