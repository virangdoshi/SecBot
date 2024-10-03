# export SLACK_BOT_TOKEN=xoxb-your-token
# export SLACK_SIGNING_SECRET=your-signing-secret
# export OPENAI_API_KEY=XX
import json
import os
from openai import OpenAI

from slack_bolt import App
from security import safe_requests

client = OpenAI()
# Initializes your app with your bot token and signing secret
app = App(
    token=os.environ.get("SLACK_BOT_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET"),
)


def handle_msg(msg):
    # msg is the user supplied input

    # Send the user prompt to OpenAI moderation API
    moderation_user_prompt_response = client.moderations.create(input=msg)
    res = moderation_user_prompt_response.results[0]
    print(res)
    is_flagged = res.flagged
    details = res.categories.__dict__
    # Check if the user input is flagged by the moderation API
    if is_flagged:
        print(json.dumps(details, indent=2))
        return (
            "```"
            + "There was a problem between keyboard and chair\n"
            + json.dumps(details, indent=2)
            + "```"
        )

    response = client.chat.completions.create(
        model="gpt-4o-mini-2024-07-18",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": msg},
        ],
        temperature=0.6,
        max_completion_tokens=150000,
    )
    print(response)
    moderation_openai_prompt_response = client.moderations.create(
        input=response.choices[0].message.content
    )
    res = moderation_openai_prompt_response.results[0]
    print(res)
    is_flagged = res.flagged
    details = res.categories.__dict__
    # Check if the prompt response is flagged by the moderation API
    if is_flagged:
        print(json.dumps(details, indent=2))
        return (
            "```"
            + "There was a problem with the response\n"
            + json.dumps(details, indent=2)
            + "```"
        )

    res = str(response.choices[0].message.content)
    return "```" + res + "```"


def cve_search(cve):
    r = safe_requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve)
    r = json.loads(r.content)
    r = r["vulnerabilities"][0]["cve"]
    # print(r['configurations'])
    vuln_name = r["cisaVulnerabilityName"]
    vuln_description = r["descriptions"][0]["value"]
    vuln_references = r["references"]
    return str(
        "```"
        + vuln_name
        + "```"
        + "\n"
        + "```"
        + vuln_description
        + "```"
        + "\n"
        + "```"
        + str(vuln_references[0]["url"])
        + "```"
    )


def package_cve_search(package):
    r = safe_requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + package
    )

    # print(r.content)
    r = json.loads(r.content)
    r = r["vulnerabilities"]
    # print(r[0])

    json_formatted_str = json.dumps(r[0], indent=4)
    print(json_formatted_str)
    s = ""
    for entry in r:
        # print(entry['cve'])
        s += "```" + entry["cve"]["id"] + "\n"
        s += entry["cve"]["descriptions"][0]["value"] + "```\n\n"

    return s
    # print(r.keys())


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

    msg = event["blocks"][0]["elements"][0]["elements"][1]["text"]

    if msg.split()[0] == "cve_search":
        res = cve_search(msg.split()[1])

    elif msg.split()[0] == "package_search":
        res = package_cve_search((msg.split()[1]))
    else:
        res = handle_msg(msg)

    client.chat_postMessage(
        channel=event["channel"],
        thread_ts=event["ts"],
        text=res,
        parse="full",
    )


# TODO add SaaS vendors to this list
keywords = [
    "test",
    "java",
    "python",
    "supply",
    "chain",
    "github",
    "macos",
    "snyk",
    "cve",
    "pypi",
    "package",
]


@app.event("message")
def handle_message_events(client, body, event, logger):
    # print(json.dumps(body, indent=4))
    print(body["event"]["text"])
    for word in keywords:
        if word.lower() in body["event"]["text"].lower():
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


# Start your app
if __name__ == "__main__":
    # moderation_user_prompt_response = client.moderations.create(input="msg")
    # res = moderation_user_prompt_response
    # print(res.results[0].flagged)
    # print(json.dumps(res.results[0].categories.__dict__, indent=2))

    app.start(port=int(os.environ.get("PORT", 3000)))

    print(cve_search("CVE-2021-44228"))
    package_cve_search("redis")
