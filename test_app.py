import pytest
import json
import os
from unittest.mock import Mock, patch, MagicMock, mock_open
from slack_bolt import App


class TestAppConfiguration:
    """Test cases for app configuration and initialization."""
    
    @patch('app.json.load')
    @patch('builtins.open', new_callable=mock_open)
    @patch.dict(os.environ, {
        'OPENAI_API_KEY': 'test-openai-key',
        'SLACK_BOT_TOKEN': 'xoxb-test-token',
        'SLACK_SIGNING_SECRET': 'test-signing-secret'
    })
    def test_config_loading(self, mock_file, mock_json_load):
        """Test that configuration is loaded correctly."""
        mock_config = {
            "keywords": ["test", "security"],
            "max_cve_results": 5,
            "openai_model": "gpt-4o-mini"
        }
        mock_json_load.return_value = mock_config
        
        # Import app module to trigger config loading
        import app
        
        mock_file.assert_called_once_with("config.json", "r")
        mock_json_load.assert_called_once()
        assert app.config == mock_config


class TestHomeTabHandler:
    """Test cases for the home tab handler."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.mock_event = {"user": "U123456"}
        self.mock_logger = Mock()
    
    @patch('app.update_home_tab')
    def test_update_home_tab_success(self, mock_update_home_tab):
        """Test successful home tab update."""
        from app import update_home_tab
        
        # Call the function directly
        update_home_tab(self.mock_client, self.mock_event, self.mock_logger)
        
        # Verify views.publish was called
        self.mock_client.views_publish.assert_called_once()
        call_args = self.mock_client.views_publish.call_args
        
        # Check user_id
        assert call_args[1]["user_id"] == "U123456"
        
        # Check view structure
        view = call_args[1]["view"]
        assert view["type"] == "home"
        assert view["callback_id"] == "home_view"
        assert len(view["blocks"]) == 4  # section, divider, section, actions
    
    @patch('app.update_home_tab')
    def test_update_home_tab_exception(self, mock_update_home_tab):
        """Test home tab update with exception."""
        from app import update_home_tab
        
        self.mock_client.views_publish.side_effect = Exception("API Error")
        
        update_home_tab(self.mock_client, self.mock_event, self.mock_logger)
        
        # Verify error was logged
        self.mock_logger.error.assert_called_once()
        error_call = self.mock_logger.error.call_args[0][0]
        assert "Error publishing home tab" in error_call


class TestMentionHandler:
    """Test cases for the app mention handler."""
    
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
    
    @patch('app.config', new_callable=lambda: {"keywords": ["test"]})
    @patch('app.respond_to_mention')
    def test_respond_to_mention_empty_message(self, mock_respond_to_mention):
        """Test response to empty mention."""
        from app import respond_to_mention
        
        mock_event = self.create_mock_event("")
        
        respond_to_mention(self.mock_client, mock_event, self.mock_logger)
        
        # Verify response message
        self.mock_client.chat_postMessage.assert_called_once()
        call_args = self.mock_client.chat_postMessage.call_args[1]
        assert "Please provide a command" in call_args["text"]
        assert call_args["channel"] == "C123456"
        assert call_args["thread_ts"] == "1234567890.123456"
    
    @patch('app.cve_search')
    @patch('app.config', new_callable=lambda: {"keywords": ["test"]})
    @patch('app.respond_to_mention')
    def test_respond_to_mention_cve_search(self, mock_respond_to_mention, mock_cve_search):
        """Test CVE search command."""
        from app import respond_to_mention
        
        mock_cve_search.return_value = "CVE details here"
        mock_event = self.create_mock_event("cve_search CVE-2021-44228")
        
        respond_to_mention(self.mock_client, mock_event, self.mock_logger)
        
        # Verify CVE search was called
        mock_cve_search.assert_called_once()
        
        # Verify response
        self.mock_client.chat_postMessage.assert_called_once()
        call_args = self.mock_client.chat_postMessage.call_args[1]
        assert call_args["text"] == "CVE details here"
    
    @patch('app.cve_search')
    @patch('app.config', new_callable=lambda: {"keywords": ["test"]})
    @patch('app.respond_to_mention')
    def test_respond_to_mention_cve_search_no_id(self, mock_respond_to_mention, mock_cve_search):
        """Test CVE search command without CVE ID."""
        from app import respond_to_mention
        
        mock_event = self.create_mock_event("cve_search")
        
        respond_to_mention(self.mock_client, mock_event, self.mock_logger)
        
        # Verify CVE search was not called
        mock_cve_search.assert_not_called()
        
        # Verify error response
        self.mock_client.chat_postMessage.assert_called_once()
        call_args = self.mock_client.chat_postMessage.call_args[1]
        assert "Please provide a CVE ID" in call_args["text"]
    
    @patch('app.package_cve_search')
    @patch('app.config', new_callable=lambda: {"keywords": ["test"]})
    @patch('app.respond_to_mention')
    def test_respond_to_mention_package_search(self, mock_respond_to_mention, mock_package_cve_search):
        """Test package search command."""
        from app import respond_to_mention
        
        mock_package_cve_search.return_value = "Package vulnerabilities here"
        mock_event = self.create_mock_event("package_search log4j")
        
        respond_to_mention(self.mock_client, mock_event, self.mock_logger)
        
        # Verify package search was called
        mock_package_cve_search.assert_called_once()
        
        # Verify response
        self.mock_client.chat_postMessage.assert_called_once()
        call_args = self.mock_client.chat_postMessage.call_args[1]
        assert call_args["text"] == "Package vulnerabilities here"
    
    @patch('app.handle_msg')
    @patch('app.client')  # Mock the OpenAI client
    @patch('app.config', new_callable=lambda: {"keywords": ["test"]})
    @patch('app.respond_to_mention')
    def test_respond_to_mention_general_query(self, mock_respond_to_mention, mock_config, mock_openai_client, mock_handle_msg):
        """Test general query handling."""
        from app import respond_to_mention
        
        mock_handle_msg.return_value = "AI response here"
        mock_event = self.create_mock_event("What is Python?")
        
        respond_to_mention(self.mock_client, mock_event, self.mock_logger)
        
        # Verify handle_msg was called
        mock_handle_msg.assert_called_once()
        
        # Verify response
        self.mock_client.chat_postMessage.assert_called_once()
        call_args = self.mock_client.chat_postMessage.call_args[1]
        assert call_args["text"] == "AI response here"
    
    @patch('app.config', new_callable=lambda: {"keywords": ["test"]})
    @patch('app.respond_to_mention')
    def test_respond_to_mention_exception(self, mock_respond_to_mention):
        """Test exception handling in mention response."""
        from app import respond_to_mention
        
        # Create malformed event to trigger exception
        mock_event = {"channel": "C123456", "ts": "1234567890.123456", "blocks": []}
        
        respond_to_mention(self.mock_client, mock_event, self.mock_logger)
        
        # Verify error was logged
        self.mock_logger.error.assert_called_once()
        
        # Verify error response was sent
        self.mock_client.chat_postMessage.assert_called_once()
        call_args = self.mock_client.chat_postMessage.call_args[1]
        assert "An error occurred" in call_args["text"]


class TestMessageHandler:
    """Test cases for the message handler."""
    
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
    
    @patch('app.keywords', new=["security", "vulnerability"])
    @patch('app.handle_message_events')
    def test_handle_message_events_keyword_match(self, mock_handle_message_events):
        """Test message handling when keyword is found."""
        from app import handle_message_events
        
        body, event = self.create_mock_body_and_event("There's a new security vulnerability")
        
        handle_message_events(self.mock_client, body, event, self.mock_logger)
        
        # Verify message was posted
        self.mock_client.chat_postMessage.assert_called_once()
        call_args = self.mock_client.chat_postMessage.call_args[1]
        assert call_args["channel"] == "C123456"
        assert call_args["thread_ts"] == "1234567890.123456"
        assert "check this out" in call_args["blocks"][0]["text"]["text"]
    
    @patch('app.keywords', new=["security", "vulnerability"])
    @patch('app.handle_message_events')
    def test_handle_message_events_no_keyword_match(self, mock_handle_message_events):
        """Test message handling when no keyword is found."""
        from app import handle_message_events
        
        body, event = self.create_mock_body_and_event("Just a regular message")
        
        handle_message_events(self.mock_client, body, event, self.mock_logger)
        
        # Verify no message was posted
        self.mock_client.chat_postMessage.assert_not_called()
    
    @patch('app.keywords', new=["security", "vulnerability"])
    @patch('app.handle_message_events')
    def test_handle_message_events_case_insensitive(self, mock_handle_message_events):
        """Test that keyword matching is case insensitive."""
        from app import handle_message_events
        
        body, event = self.create_mock_body_and_event("SECURITY alert!")
        
        handle_message_events(self.mock_client, body, event, self.mock_logger)
        
        # Verify message was posted
        self.mock_client.chat_postMessage.assert_called_once()
    
    @patch('app.keywords', new=["security", "vulnerability"])
    @patch('app.handle_message_events')
    def test_handle_message_events_multiple_keywords(self, mock_handle_message_events):
        """Test that only one message is posted even with multiple keyword matches."""
        from app import handle_message_events
        
        body, event = self.create_mock_body_and_event("security vulnerability detected")
        
        handle_message_events(self.mock_client, body, event, self.mock_logger)
        
        # Verify only one message was posted (due to break statement)
        self.mock_client.chat_postMessage.assert_called_once()
    
    @patch('app.keywords', new=["security"])
    @patch('app.handle_message_events')
    def test_handle_message_events_exception(self, mock_handle_message_events):
        """Test exception handling in message events."""
        from app import handle_message_events
        
        # Create malformed body to trigger exception
        body = {"event": {}}  # Missing 'text' key
        event = {"channel": "C123456", "ts": "1234567890.123456"}
        
        handle_message_events(self.mock_client, body, event, self.mock_logger)
        
        # Verify error was logged
        self.mock_logger.error.assert_called_once()


class TestAppIntegration:
    """Integration tests for the app."""
    
    @patch.dict(os.environ, {
        'OPENAI_API_KEY': 'test-openai-key',
        'SLACK_BOT_TOKEN': 'xoxb-test-token',
        'SLACK_SIGNING_SECRET': 'test-signing-secret',
        'PORT': '3000'
    })
    @patch('app.json.load')
    @patch('builtins.open', new_callable=mock_open)
    def test_app_initialization(self, mock_file, mock_json_load):
        """Test that the app initializes correctly."""
        mock_config = {"keywords": ["test"], "max_cve_results": 5}
        mock_json_load.return_value = mock_config
        
        # Import app module
        import app
        
        # Verify app is initialized
        assert isinstance(app.app, App)
        assert app.config == mock_config
    
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_environment_variables(self):
        """Test behavior when environment variables are missing."""
        # This would typically cause the app to fail initialization
        # The actual behavior depends on how Slack Bolt handles missing tokens
        pass  # This test would need to be more specific based on error handling


if __name__ == "__main__":
    pytest.main([__file__])
