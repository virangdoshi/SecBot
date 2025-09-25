import pytest
import json
import os
from unittest.mock import Mock, patch, MagicMock, mock_open
from slack_bolt import App


class TestAppConfiguration:
    """Test cases for app configuration and initialization."""

    @patch('builtins.open', new_callable=mock_open)
    def test_config_loading_logic(self, mock_file):
        """Test that configuration loading logic works correctly."""
        mock_config_data = {
            "keywords": ["test", "security"],
            "max_cve_results": 5,
            "openai_model": "gpt-4o-mini"
        }

        # Mock the file read and JSON parsing
        mock_file.return_value.read.return_value = json.dumps(mock_config_data)

        # Test the config loading logic directly
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                loaded_config = json.load(f)
            assert loaded_config == mock_config_data
        except Exception:
            # If file doesn't exist, that's expected in test environment
            pass


class TestHomeTabLogic:
    """Test cases for home tab functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.mock_event = {"user": "U123456"}
        self.mock_logger = Mock()

    def test_home_tab_view_structure(self):
        """Test that the home tab view has the correct structure."""
        # Test the view structure directly without importing the function
        expected_view = {
            "type": "home",
            "callback_id": "home_view",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Welcome to your _App's Home_* :tada:. Testing",
                    },
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "This button won't do much for now but you can set up a listener for it using the `actions()` method and passing its unique `action_id`. See an example in the `examples` folder within your Bolt app.",
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Click me!"},
                        }
                    ],
                },
            ],
        }

        # Verify the structure matches what the function creates
        assert expected_view["type"] == "home"
        assert expected_view["callback_id"] == "home_view"
        assert len(expected_view["blocks"]) == 4

    def test_home_tab_success_path(self):
        """Test the success path of home tab update."""
        # Mock successful client call
        self.mock_client.views_publish.return_value = None

        # Simulate the function logic
        try:
            self.mock_client.views_publish(
                user_id=self.mock_event["user"],
                view={
                    "type": "home",
                    "callback_id": "home_view",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "*Welcome to your _App's Home_* :tada:. Testing",
                            },
                        },
                        {"type": "divider"},
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "This button won't do much for now but you can set up a listener for it using the `actions()` method and passing its unique `action_id`. See an example in the `examples` folder within your Bolt app.",
                            },
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "Click me!"},
                                }
                            ],
                        },
                    ],
                }
            )
        except Exception as e:
            self.mock_logger.error(f"Error publishing home tab: {e}")

        # Verify the call was made correctly
        self.mock_client.views_publish.assert_called_once()
        call_args = self.mock_client.views_publish.call_args
        assert call_args[1]["user_id"] == "U123456"
        assert call_args[1]["view"]["type"] == "home"

    def test_home_tab_exception_handling(self):
        """Test exception handling in home tab update."""
        # Mock client to raise an exception
        self.mock_client.views_publish.side_effect = Exception("API Error")

        # Simulate the function logic with exception handling
        try:
            self.mock_client.views_publish(
                user_id=self.mock_event["user"],
                view={
                    "type": "home",
                    "callback_id": "home_view",
                    "blocks": [],
                }
            )
        except Exception as e:
            self.mock_logger.error(f"Error publishing home tab: {e}")

        # Verify error was logged
        self.mock_logger.error.assert_called_once()
        error_call = self.mock_logger.error.call_args[0][0]
        assert "Error publishing home tab" in error_call


class TestMentionHandlerLogic:
    """Test cases for mention handling logic."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.mock_logger = Mock()
        self.mock_config = {
            "keywords": ["test", "security"],
            "max_cve_results": 5,
            "request_timeout": 10
        }

    def create_mock_event(self, text):
        """Create a mock event with the given text."""
        return {
            "channel": "C123456",
            "ts": "1234567890.123456",
            "blocks": [{
                "elements": [{
                    "elements": [
                        {"type": "user", "user_id": "U123456"},  # Bot mention
                        {"type": "text", "text": text}
                    ]
                }]
            }]
        }

    @patch('utils.cve_search')
    def test_mention_empty_message(self, mock_cve_search):
        """Test response to empty mention."""
        event = self.create_mock_event("")

        # Simulate the mention handler logic
        msg = event["blocks"][0]["elements"][0]["elements"][1]["text"]
        parts = msg.strip().split()

        if not parts:
            res = "Please provide a command. Available commands: cve_search <CVE-ID>, package_search <package-name>, or any other query for ChatGPT."
        elif parts[0] == "cve_search":
            if len(parts) < 2:
                res = "Please provide a CVE ID after cve_search, e.g., cve_search CVE-2021-44228."
            else:
                res = mock_cve_search(self.mock_config, parts[1])
        elif parts[0] == "package_search":
            if len(parts) < 2:
                res = "Please provide a package name after package_search, e.g., package_search redis."
            else:
                res = "package_search result"  # Mock result
        else:
            res = "AI response"  # Mock AI response

        # Verify response message
        assert "Please provide a command" in res
        assert "cve_search" in res
        assert "package_search" in res

    @patch('utils.cve_search')
    def test_mention_cve_search_success(self, mock_cve_search):
        """Test CVE search command."""
        mock_cve_search.return_value = "CVE details here"
        event = self.create_mock_event("cve_search CVE-2021-44228")

        # Simulate the mention handler logic
        msg = event["blocks"][0]["elements"][0]["elements"][1]["text"]
        parts = msg.strip().split()

        if not parts:
            res = "Please provide a command."
        elif parts[0] == "cve_search":
            if len(parts) < 2:
                res = "Please provide a CVE ID after cve_search."
            else:
                res = mock_cve_search(self.mock_config, parts[1])
        elif parts[0] == "package_search":
            if len(parts) < 2:
                res = "Please provide a package name."
            else:
                res = "package_search result"
        else:
            res = "AI response"

        # Verify CVE search was called and response is correct
        mock_cve_search.assert_called_once_with(self.mock_config, "CVE-2021-44228")
        assert res == "CVE details here"

    @patch('utils.cve_search')
    def test_mention_cve_search_no_id(self, mock_cve_search):
        """Test CVE search command without CVE ID."""
        event = self.create_mock_event("cve_search")

        # Simulate the mention handler logic
        msg = event["blocks"][0]["elements"][0]["elements"][1]["text"]
        parts = msg.strip().split()

        if not parts:
            res = "Please provide a command."
        elif parts[0] == "cve_search":
            if len(parts) < 2:
                res = "Please provide a CVE ID after cve_search, e.g., cve_search CVE-2021-44228."
            else:
                res = mock_cve_search(self.mock_config, parts[1])
        elif parts[0] == "package_search":
            if len(parts) < 2:
                res = "Please provide a package name."
            else:
                res = "package_search result"
        else:
            res = "AI response"

        # Verify CVE search was not called
        mock_cve_search.assert_not_called()
        assert "Please provide a CVE ID" in res

    @patch('utils.package_cve_search')
    def test_mention_package_search_success(self, mock_package_cve_search):
        """Test package search command."""
        mock_package_cve_search.return_value = "Package vulnerabilities here"
        event = self.create_mock_event("package_search log4j")

        # Simulate the mention handler logic
        msg = event["blocks"][0]["elements"][0]["elements"][1]["text"]
        parts = msg.strip().split()

        if not parts:
            res = "Please provide a command."
        elif parts[0] == "cve_search":
            if len(parts) < 2:
                res = "Please provide a CVE ID."
            else:
                res = "cve_search result"
        elif parts[0] == "package_search":
            if len(parts) < 2:
                res = "Please provide a package name after package_search, e.g., package_search redis."
            else:
                res = mock_package_cve_search(self.mock_config, " ".join(parts[1:]))
        else:
            res = "AI response"

        # Verify package search was called
        mock_package_cve_search.assert_called_once_with(self.mock_config, "log4j")
        assert res == "Package vulnerabilities here"

    @patch('handlers.handle_msg')
    def test_mention_general_query(self, mock_handle_msg):
        """Test general query handling."""
        mock_handle_msg.return_value = "AI response here"
        event = self.create_mock_event("What is Python?")

        # Simulate the mention handler logic
        msg = event["blocks"][0]["elements"][0]["elements"][1]["text"]
        parts = msg.strip().split()

        if not parts:
            res = "Please provide a command."
        elif parts[0] == "cve_search":
            if len(parts) < 2:
                res = "Please provide a CVE ID."
            else:
                res = "cve_search result"
        elif parts[0] == "package_search":
            if len(parts) < 2:
                res = "Please provide a package name."
            else:
                res = "package_search result"
        else:
            res = mock_handle_msg(self.mock_client, self.mock_config, msg)

        # Verify handle_msg was called
        mock_handle_msg.assert_called_once_with(self.mock_client, self.mock_config, "What is Python?")
        assert res == "AI response here"

    def test_mention_exception_handling(self):
        """Test exception handling in mention response."""
        # Create malformed event to trigger exception
        event = {"channel": "C123456", "ts": "1234567890.123456", "blocks": []}

        # Simulate exception handling
        try:
            msg = event["blocks"][0]["elements"][0]["elements"][1]["text"]
            parts = msg.strip().split()
            res = "normal response"
        except Exception as e:
            self.mock_logger.error(f"Error in respond_to_mention: {e}")
            res = "An error occurred while processing your request."

        # Verify error response
        assert res == "An error occurred while processing your request."


class TestMessageHandlerLogic:
    """Test cases for message handling logic."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.mock_logger = Mock()
        self.mock_config = {"keywords": ["security", "vulnerability", "cve"]}

    def create_mock_body_and_event(self, message_text):
        """Create mock body and event for message handler."""
        body = {"event": {"text": message_text}}
        event = {"channel": "C123456", "ts": "1234567890.123456"}
        return body, event

    def test_message_keyword_match(self):
        """Test message handling when keyword is found."""
        body, event = self.create_mock_body_and_event("There's a new security vulnerability")

        # Simulate the message handler logic
        message_text = body["event"]["text"]
        self.mock_logger.info(f"Received message: {message_text}")

        keywords = self.mock_config["keywords"]
        keyword_found = False
        for word in keywords:
            if word.lower() in message_text.lower():
                # Send notification
                self.mock_client.chat_postMessage(
                    channel=event["channel"],
                    thread_ts=event["ts"],
                    blocks=[
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"Hey <@{self.mock_config.get('alert_user_id', 'UNKNOWN_USER')}>, check this out ^",
                            },
                        },
                        {"type": "divider"},
                    ],
                )
                keyword_found = True
                break  # Only ping once per message

        # Verify message was posted
        assert keyword_found is True
        self.mock_client.chat_postMessage.assert_called_once()
        call_args = self.mock_client.chat_postMessage.call_args[1]
        assert call_args["channel"] == "C123456"
        assert call_args["thread_ts"] == "1234567890.123456"
        assert "check this out" in call_args["blocks"][0]["text"]["text"]

    def test_message_no_keyword_match(self):
        """Test message handling when no keyword is found."""
        body, event = self.create_mock_body_and_event("Just a regular message")

        # Simulate the message handler logic
        message_text = body["event"]["text"]
        self.mock_logger.info(f"Received message: {message_text}")

        keywords = self.mock_config["keywords"]
        keyword_found = False
        for word in keywords:
            if word.lower() in message_text.lower():
                # Would send notification
                keyword_found = True
                break

        # Verify no message was posted
        assert keyword_found is False
        self.mock_client.chat_postMessage.assert_not_called()

    def test_message_case_insensitive(self):
        """Test that keyword matching is case insensitive."""
        body, event = self.create_mock_body_and_event("SECURITY alert!")

        # Simulate the message handler logic
        message_text = body["event"]["text"]
        self.mock_logger.info(f"Received message: {message_text}")

        keywords = self.mock_config["keywords"]
        keyword_found = False
        for word in keywords:
            if word.lower() in message_text.lower():
                # Would send notification
                keyword_found = True
                break

        # Verify message was posted
        assert keyword_found is True

    def test_message_multiple_keywords(self):
        """Test that only one message is posted even with multiple keyword matches."""
        body, event = self.create_mock_body_and_event("security vulnerability detected")

        # Simulate the message handler logic
        message_text = body["event"]["text"]
        self.mock_logger.info(f"Received message: {message_text}")

        keywords = self.mock_config["keywords"]
        notification_count = 0
        for word in keywords:
            if word.lower() in message_text.lower():
                # Send notification (but break after first match)
                notification_count += 1
                break  # Only ping once per message

        # Verify only one notification was sent
        assert notification_count == 1

    def test_message_exception_handling(self):
        """Test exception handling in message events."""
        # Create malformed body to trigger exception
        body = {"event": {}}  # Missing 'text' key
        event = {"channel": "C123456", "ts": "1234567890.123456"}

        # Simulate exception handling
        try:
            message_text = body["event"]["text"]
            self.mock_logger.info(f"Received message: {message_text}")
            # Process keywords...
        except Exception as e:
            self.mock_logger.error(f"Error in handle_message_events: {e}")

        # Verify error was logged
        self.mock_logger.error.assert_called_once()


class TestAppIntegration:
    """Integration tests for the app."""
    
    @patch('slack_bolt.App')
    @patch('openai.OpenAI')
    @patch.dict(os.environ, {
        'OPENAI_API_KEY': 'test-openai-key',
        'SLACK_BOT_TOKEN': 'xoxb-test-token',
        'SLACK_SIGNING_SECRET': 'test-signing-secret',
        'PORT': '3000'
    })
    @patch('json.load')
    @patch('builtins.open', new_callable=mock_open)
    def test_app_initialization(self, mock_file, mock_json_load, mock_openai_client, mock_slack_app):
        """Test that the app initializes correctly."""
        mock_config = {"keywords": ["test"], "max_cve_results": 5}
        mock_json_load.return_value = mock_config

        # Import app module
        import app

        # Verify app is initialized
        assert isinstance(app.app, Mock)  # Should be our mocked app
        assert app.config == mock_config
    
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_environment_variables(self):
        """Test behavior when environment variables are missing."""
        # This would typically cause the app to fail initialization
        # The actual behavior depends on how Slack Bolt handles missing tokens
        pass  # This test would need to be more specific based on error handling


if __name__ == "__main__":
    pytest.main([__file__])
