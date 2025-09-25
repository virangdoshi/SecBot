import logging
from typing import Dict, List, Any
from openai import OpenAI, OpenAIError

logger = logging.getLogger(__name__)

def handle_msg(client: OpenAI, config: Dict[str, Any], msg: str) -> str:
    """Handle user message with OpenAI moderation and chat completion."""
    try:
        # Send the user prompt to OpenAI moderation API
        moderation_user_prompt_response = client.moderations.create(model=config["moderation_model"], input=msg)
        res = moderation_user_prompt_response.results[0]
        logger.info(f"Moderation result for user input: {res}")
        is_flagged = res.flagged
        details = res.categories.__dict__
        # Check if the user input is flagged by the moderation API
        if is_flagged:
            logger.warning(f"User input flagged: {details}")
            return (
                "```"
                + "There was a problem between keyboard and chair\n"
                + str(details)
                + "```"
            )

        response = client.chat.completions.create(
            model=config["openai_model"],
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": msg},
            ],
            temperature=0.6,
            max_completion_tokens=config["max_completion_tokens"],
        )
        logger.info("Chat completion response received")
        moderation_openai_prompt_response = client.moderations.create(
            model=config["moderation_model"],
            input=response.choices[0].message.content
        )
        res = moderation_openai_prompt_response.results[0]
        logger.info(f"Moderation result for AI response: {res}")
        is_flagged = res.flagged
        details = res.categories.__dict__
        # Check if the prompt response is flagged by the moderation API
        if is_flagged:
            logger.warning(f"AI response flagged: {details}")
            return (
                "```"
                + "There was a problem with the response\n"
                + str(details)
                + "```"
            )

        res = str(response.choices[0].message.content)
        return "```" + res + "```"
    except OpenAIError as e:
        logger.error(f"OpenAI API error: {e}")
        return "Sorry, there was an error processing your request with OpenAI."
    except Exception as e:
        logger.error(f"Unexpected error in handle_msg: {e}")
        return "An unexpected error occurred."
