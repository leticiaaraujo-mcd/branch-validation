import os
import hmac
import hashlib
import json
import re
from github import Github, GithubIntegration
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

APP_ID = "327238"
PRIVATE_KEY = ""

WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]
INSTALLATION_ID = int(os.environ["INSTALLATION_ID"])
REPOSITORY_OWNER = "leticiaaraujo-mcd"
REPOSITORY_NAME = "git-hooks"


def handler(event, context):
    body = event["body"]
    headers = event["headers"]
    github_event = headers["x-github-event"]
    signature = headers["x-hub-signature"]

    # Verify the webhook signature
    if not verify_webhook(body.encode(), signature.encode(), WEBHOOK_SECRET.encode()):
        print("Invalid signature, returning 401 Unauthorized")
        return {
            "statusCode": 401,
            "body": json.dumps({"message": "Unauthorized"}),
        }

    print(f"Received {github_event} event")
    print(f"Body: {body}")

    # Handle the push event
    if github_event == "push":
        push_event = json.loads(body)
        branch_name = push_event["ref"].split("/")[-1]

        # Validate the branch name
        if not validate_branch_name(branch_name):
            print(f"Blocking push to {branch_name}")
            github = get_github_client()
            repo = github.get_repo(f"{REPOSITORY_OWNER}/{REPOSITORY_NAME}")
            commit = repo.get_commit(push_event["after"])
            commit.create_status(
                state="error",
                context="branch-name-validation",
                description=f'Branch name "{branch_name}" does not match the required format (feature/{{ISSUE_KEY}}-{{ISSUE_NUMBER}})',
            )

            return {
                "statusCode": 422,
                "body": json.dumps({"message": "Branch name validation failed"}),
            }

    return {"statusCode": 200}


def verify_webhook(payload, signature, secret):
    expected = hmac.new(secret, payload, hashlib.sha1).hexdigest()
    return hmac.compare_digest(expected, signature)


def validate_branch_name(branch_name):
    return bool(re.match(r"^feature/[A-Z]{3}-\d+", branch_name))


def get_github_client():
    integration = GithubIntegration(APP_ID, PRIVATE_KEY)
    access_token = integration.get_access_token(INSTALLATION_ID).token
    return Github(access_token)