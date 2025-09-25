import json
import os
import logging
from openai import OpenAI
from slack_bolt import App
from handlers import handle_msg
from utils import cve_search, package_cve_search

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
with open("config.json", "r") as f:
    config = json.load(f)

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
# Initializes your app with your bot token and signing secret
app = App(
    token=os.environ.get("SLACK_BOT_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET"),
)


# Add functionality here
# @app.event("app_home_opened") etc
@app.event("app_home_opened")
def update_home_tab(client, event, logger):
    try:
        # views.publish is the method that your app uses to push a view to the Home tab
        client.views_publish(
            # the user that opened your app's app home
            user_id=event["user"],
            # the view object that appears in the app home
            view={
                "type": "home",
                "callback_id": "home_view",
                # body of the view
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
            },
        )

    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")


@app.event("app_mention")
def respond_to_mention(client, event, logger):
    try:
        msg = event["blocks"][0]["elements"][0]["elements"][1]["text"]
        parts = msg.strip().split()
        if not parts:
            res = "Please provide a command. Available commands: cve_search <CVE-ID>, package_search <package-name>, or any other query for ChatGPT."
        elif parts[0] == "cve_search":
            if len(parts) < 2:
                res = "Please provide a CVE ID after cve_search, e.g., cve_search CVE-2021-44228."
            else:
                res = cve_search(config, parts[1])
        elif parts[0] == "package_search":
            if len(parts) < 2:
                res = "Please provide a package name after package_search, e.g., package_search redis."
            else:
                res = package_cve_search(config, " ".join(parts[1:]))
        else:
            res = handle_msg(client, config, msg)

        client.chat_postMessage(
            channel=event["channel"],
            thread_ts=event["ts"],
            text=res,
            parse="full",
        )
    except Exception as e:
        logger.error(f"Error in respond_to_mention: {e}")
        client.chat_postMessage(
            channel=event["channel"],
            thread_ts=event["ts"],
            text="An error occurred while processing your request.",
            parse="full",
        )


# TODO add SaaS vendors to this list
keywords = config["keywords"]


@app.event("message")
def handle_message_events(client, body, event, logger):
    try:
        message_text = body["event"]["text"]
        logger.info(f"Received message: {message_text}")
        for word in keywords:
            if word.lower() in message_text.lower():
                client.chat_postMessage(
                    channel=event["channel"],
                    thread_ts=event["ts"],
                    blocks=[
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "Hey <@U04D73CNNDV>, check this out ^",
                            },
                        },
                        {"type": "divider"},
                    ],
                )
                break  # Only ping once per message
    except Exception as e:
        logger.error(f"Error in handle_message_events: {e}")


# Start your app
if __name__ == "__main__":
    app.start(port=int(os.environ.get("PORT", 3000)))
