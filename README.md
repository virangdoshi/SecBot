# SecBot
A Slack bot to assist with day to day activities of a security engineer. 
Powered by OpenAI API, Slack and few other open integrations like NIST CVE DB

Features:
* It will ping you on slack when certain keywords are mentioned (hardcoded keywords). This will be hepful for cases where threat intel feeds are pumped into a slack channel
* Interact with ChatGPT right from slack.

Built with:
* Slack Bolt SDK for Python
* OpenAI lib for python

To run:
* Setup a Slack app (https://api.slack.com/tools/bolt-python). Install the app in your slack workspace
* Get the Oauth Token and signing secret for the Slack app
* Get an OpenAI API key
* Export the Oauth Token, signing secret and OpenAI key and launch app.py
