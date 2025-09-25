import pytest
from unittest.mock import Mock, MagicMock, patch
from openai import OpenAIError
from handlers import handle_msg


class TestHandleMsg:
    """Test cases for message handling functionality."""
    
    def setup_method(self):
        """Set up test configuration and mock client."""
        self.config = {
            "moderation_model": "omni-moderation-latest",
            "openai_model": "gpt-4o-mini",
            "max_completion_tokens": 150000
        }
        self.mock_client = Mock()
    
    def test_handle_msg_user_input_flagged(self):
        """Test handling when user input is flagged by moderation."""
        # Mock moderation response for user input (flagged)
        mock_moderation_result = Mock()
        mock_moderation_result.flagged = True
        mock_moderation_result.categories.__dict__ = {"harassment": True, "violence": False}
        
        mock_moderation_response = Mock()
        mock_moderation_response.results = [mock_moderation_result]
        
        self.mock_client.moderations.create.return_value = mock_moderation_response
        
        result = handle_msg(self.mock_client, self.config, "harmful message")
        
        assert "There was a problem between keyboard and chair" in result
        assert "harassment" in result
        assert "violence" in result
        
        # Verify moderation was called
        self.mock_client.moderations.create.assert_called_once_with(
            model=self.config["moderation_model"],
            input="harmful message"
        )
    
    def test_handle_msg_ai_response_flagged(self):
        """Test handling when AI response is flagged by moderation."""
        # Mock moderation response for user input (not flagged)
        mock_user_moderation_result = Mock()
        mock_user_moderation_result.flagged = False
        mock_user_moderation_response = Mock()
        mock_user_moderation_response.results = [mock_user_moderation_result]
        
        # Mock chat completion response
        mock_chat_response = Mock()
        mock_message = Mock()
        mock_message.content = "potentially harmful AI response"
        mock_choice = Mock()
        mock_choice.message = mock_message
        mock_chat_response.choices = [mock_choice]
        
        # Mock moderation response for AI output (flagged)
        mock_ai_moderation_result = Mock()
        mock_ai_moderation_result.flagged = True
        mock_ai_moderation_result.categories.__dict__ = {"hate": True, "self-harm": False}
        mock_ai_moderation_response = Mock()
        mock_ai_moderation_response.results = [mock_ai_moderation_result]
        
        # Set up mock calls in order
        self.mock_client.moderations.create.side_effect = [
            mock_user_moderation_response,  # First call for user input
            mock_ai_moderation_response     # Second call for AI response
        ]
        self.mock_client.chat.completions.create.return_value = mock_chat_response
        
        result = handle_msg(self.mock_client, self.config, "normal message")
        
        assert "There was a problem with the response" in result
        assert "hate" in result
        assert "self-harm" in result
        
        # Verify both moderation calls were made
        assert self.mock_client.moderations.create.call_count == 2
    
    def test_handle_msg_success(self):
        """Test successful message handling."""
        # Mock moderation responses (both not flagged)
        mock_moderation_result = Mock()
        mock_moderation_result.flagged = False
        mock_moderation_response = Mock()
        mock_moderation_response.results = [mock_moderation_result]
        
        # Mock chat completion response
        mock_chat_response = Mock()
        mock_message = Mock()
        mock_message.content = "This is a helpful response"
        mock_choice = Mock()
        mock_choice.message = mock_message
        mock_chat_response.choices = [mock_choice]
        
        self.mock_client.moderations.create.return_value = mock_moderation_response
        self.mock_client.chat.completions.create.return_value = mock_chat_response
        
        result = handle_msg(self.mock_client, self.config, "What is Python?")
        
        assert result == "```This is a helpful response```"
        
        # Verify chat completion was called with correct parameters
        self.mock_client.chat.completions.create.assert_called_once_with(
            model=self.config["openai_model"],
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "What is Python?"},
            ],
            temperature=0.6,
            max_completion_tokens=self.config["max_completion_tokens"],
        )
        
        # Verify both moderation calls were made
        assert self.mock_client.moderations.create.call_count == 2
    
    def test_handle_msg_openai_error(self):
        """Test handling of OpenAI API errors."""
        # Mock moderation response (not flagged)
        mock_moderation_result = Mock()
        mock_moderation_result.flagged = False
        mock_moderation_response = Mock()
        mock_moderation_response.results = [mock_moderation_result]
        
        self.mock_client.moderations.create.return_value = mock_moderation_response
        self.mock_client.chat.completions.create.side_effect = OpenAIError("API Error")
        
        result = handle_msg(self.mock_client, self.config, "test message")
        
        assert "Sorry, there was an error processing your request with OpenAI" in result
    
    def test_handle_msg_unexpected_error(self):
        """Test handling of unexpected errors."""
        # Mock moderation to raise an unexpected error
        self.mock_client.moderations.create.side_effect = ValueError("Unexpected error")
        
        result = handle_msg(self.mock_client, self.config, "test message")
        
        assert "An unexpected error occurred" in result
    
    def test_handle_msg_moderation_parameters(self):
        """Test that moderation is called with correct parameters."""
        # Mock moderation responses (both not flagged)
        mock_moderation_result = Mock()
        mock_moderation_result.flagged = False
        mock_moderation_response = Mock()
        mock_moderation_response.results = [mock_moderation_result]
        
        # Mock chat completion response
        mock_chat_response = Mock()
        mock_message = Mock()
        mock_message.content = "AI response"
        mock_choice = Mock()
        mock_choice.message = mock_message
        mock_chat_response.choices = [mock_choice]
        
        self.mock_client.moderations.create.return_value = mock_moderation_response
        self.mock_client.chat.completions.create.return_value = mock_chat_response
        
        handle_msg(self.mock_client, self.config, "test input")
        
        # Check moderation calls
        moderation_calls = self.mock_client.moderations.create.call_args_list
        
        # First call should be for user input
        assert moderation_calls[0][1]["model"] == self.config["moderation_model"]
        assert moderation_calls[0][1]["input"] == "test input"
        
        # Second call should be for AI response
        assert moderation_calls[1][1]["model"] == self.config["moderation_model"]
        assert moderation_calls[1][1]["input"] == "AI response"
    
    @patch('handlers.logger')
    def test_handle_msg_logging(self, mock_logger):
        """Test that appropriate logging occurs."""
        # Mock moderation responses (both not flagged)
        mock_moderation_result = Mock()
        mock_moderation_result.flagged = False
        mock_moderation_response = Mock()
        mock_moderation_response.results = [mock_moderation_result]
        
        # Mock chat completion response
        mock_chat_response = Mock()
        mock_message = Mock()
        mock_message.content = "AI response"
        mock_choice = Mock()
        mock_choice.message = mock_message
        mock_chat_response.choices = [mock_choice]
        
        self.mock_client.moderations.create.return_value = mock_moderation_response
        self.mock_client.chat.completions.create.return_value = mock_chat_response
        
        handle_msg(self.mock_client, self.config, "test message")
        
        # Verify logging calls
        assert mock_logger.info.call_count >= 2  # At least 2 info logs
        mock_logger.info.assert_any_call("Chat completion response received")


if __name__ == "__main__":
    pytest.main([__file__])
