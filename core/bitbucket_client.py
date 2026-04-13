"""
BitbucketClient: Posts review reports as comments on Bitbucket pull requests.
"""

import logging
import os
from typing import Protocol

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


LOGGER = logging.getLogger(__name__)


class PRClientProtocol(Protocol):
    def post_pr_comment(self, pr_id: int, body: str) -> bool:
        ...

    def is_configured(self) -> bool:
        ...


class BitbucketClient:
    """
    Thin wrapper around the Bitbucket REST API v2 for posting PR comments.

    Credentials are loaded from environment variables:
        BITBUCKET_TOKEN      — personal access token or app password
        BITBUCKET_WORKSPACE  — workspace slug (overridden by constructor arg)
        BITBUCKET_REPO       — repository slug (overridden by constructor arg)
    """

    BASE_URL = "https://api.bitbucket.org/2.0"

    def __init__(
        self,
        workspace: str | None = None,
        repo_slug: str | None = None,
        token: str | None = None,
    ):
        self.workspace = workspace or os.environ.get("BITBUCKET_WORKSPACE", "")
        self.repo_slug = repo_slug or os.environ.get("BITBUCKET_REPO", "")
        self.token = token or os.environ.get("BITBUCKET_TOKEN", "")

    
    # Public API
    

    def is_configured(self) -> bool:
        return bool(self.workspace and self.repo_slug and self.token)

    def post_pr_comment(self, pr_id: int, markdown_body: str) -> bool:
        """
        Post a markdown comment on a Bitbucket pull request.

        Returns True on success, False on failure (never raises).
        """
        if not self.is_configured():
            LOGGER.info(
                "[Bitbucket] Skipping - BITBUCKET_TOKEN / BITBUCKET_WORKSPACE / BITBUCKET_REPO not set."
            )
            return False

        if not HAS_REQUESTS:
            LOGGER.info("[Bitbucket] Skipping - 'requests' package not installed.")
            return False

        url = (
            f"{self.BASE_URL}/repositories/"
            f"{self.workspace}/{self.repo_slug}/pullrequests/{pr_id}/comments"
        )
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        payload = {"content": {"raw": markdown_body}}

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            if response.status_code in (200, 201):
                LOGGER.info("[Bitbucket] Comment posted to PR #%s.", pr_id)
                return True
            else:
                LOGGER.warning(
                    "[Bitbucket] Failed to post comment: HTTP %s - %s",
                    response.status_code,
                    response.text[:200],
                )
                return False
        except requests.RequestException as exc:
            LOGGER.warning("[Bitbucket] Request error: %s", exc)
            return False

    def get_pr_diff(self, pr_id: int) -> str | None:
        """
        Fetch the unified diff for a PR (optional helper).

        Returns diff text or None on failure.
        """
        if not self.is_configured() or not HAS_REQUESTS:
            return None

        url = (
            f"{self.BASE_URL}/repositories/"
            f"{self.workspace}/{self.repo_slug}/pullrequests/{pr_id}/diff"
        )
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                return response.text
            return None
        except requests.RequestException:
            return None
