# Copyright (c) 2025 EPAM Systems

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests
import time
from datetime import datetime, timezone
from github import Github, GithubException
from gitrepomanager.common.logging_utils import log_message
from gitrepomanager.common.logging_utils import LogLevel


def authenticate_to_github(*, access_token, enterprise_url=None):
    try:
        if enterprise_url:
            github_object = Github(
                base_url=f"{enterprise_url}/api/v3", login_or_token=access_token
            )
        else:  # github.com
            github_object = Github(access_token)
        return github_object
    except GithubException as e:
        raise (f"An error occurred while authenticating to GitHub: {e}")


def create_or_update_github_webhook(
    *,
    github_repo,
    webhook_config,
    indent_level=0,
):
    """
    Create or update a webhook on a repository.

    Args:
        github_repo: The repository object.
        webhook_config: A dictionary containing the webhook configuration. Expected keys:
            - url: The URL for the webhook.
            - events: A list of events the webhook should trigger on (default: ["push"]).
            - secret: The secret for the webhook (optional).
            - content_type: The content type for the webhook payload (default: "json").
            - insecure_ssl: Whether to allow insecure SSL (default: "0").
            - active: Whether the webhook should be active (default: True).
        indent_level: The indentation level for logging.

    Returns:
        The created or updated webhook object, or None if an error occurs.
    """
    try:
        url = webhook_config.get("url")
        if not url:
            raise ValueError("Webhook configuration must include a 'url' key.")

        active = webhook_config.get("active", True)
        content_type = webhook_config.get("content_type", "json")
        events = webhook_config.get("events", ["push"])
        insecure_ssl = webhook_config.get("insecure_ssl", "0")
        name = "web"  # only value accepted by github api
        secret = webhook_config.get("secret")

        # Check if a webhook with the same URL already exists
        existing_hooks = github_repo.get_hooks()
        for hook in existing_hooks:
            if hook.config.get("url") == url:
                # Update the existing webhook if necessary
                hook.edit(
                    name=name,
                    config={
                        "url": url,
                        "content_type": content_type,
                        "secret": secret,
                        "insecure_ssl": insecure_ssl,
                    },
                    events=events,
                    active=active,
                )
                log_message(
                    LogLevel.INFO,
                    f"Updated existing webhook for URL '{url}' on repository '{github_repo.full_name}'",
                    indent_level=indent_level,
                )
                return hook

        # Create a new webhook if no existing one matches
        new_hook = github_repo.create_hook(
            name=name,
            config={
                "url": url,
                "content_type": content_type,
                "secret": secret,
                "insecure_ssl": insecure_ssl,
            },
            events=events,
            active=active,
        )
        log_message(
            LogLevel.INFO,
            f"Created new webhook for URL '{url}' on repository '{github_repo.full_name}'",
            indent_level=indent_level,
        )
        return new_hook

    except GithubException as e:
        log_message(
            LogLevel.ERROR,
            f"Failed to create or update webhook for URL '{url}' on repository '{github_repo.full_name}': {e}",
            indent_level=indent_level,
        )
        return None


def get_github_info(*, github_target, github_user_login=None, indent_level=0):
    if not github_user_login:
        github_user_login = github_target.get_user().login
    log_message(LogLevel.INFO, "GitHub information:", indent_level=indent_level)
    log_message(
        LogLevel.INFO,
        "GitHub user: {}",
        github_user_login,
        indent_level=indent_level + 1,
    )
    return github_user_login


def get_github_repo_owner_type_plan(*, github_target, repo_owner, repo_name):
    try:
        repo = github_target.get_repo(f"{repo_owner}/{repo_name}")
        if repo.owner.type.lower() == "organization":
            type = "organization"
            org = github_target.get_organization(repo_owner)
            plan = org.plan.name  # e.g. "free", "team", "enterprise"
            return type, plan
        else:
            type = "user"
            return type, None
    except GithubException as e:
        log_message(
            LogLevel.ERROR, f"Failed to get GitHub repo owner plan: {e}", indent_level=1
        )
        return None


def get_github_repo_url(*, github_target, repo_name, repo_owner, indent_level=0):
    try:
        repo = github_target.get_repo(f"{repo_owner}/{repo_name}")
        repo_url = repo.clone_url
        log_message(
            LogLevel.DEBUG,
            f"Repository URL for '{repo_owner}/{repo_name}' is '{repo_url}'",
            indent_level=indent_level,
        )
        return repo_url
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"Failed to get repository URL for '{repo_owner}/{repo_name}': {e}",
            indent_level=indent_level + 1,
        )
        return None


def get_github_user_plan(*, github_target):
    try:
        user = github_target.get_user()
        plan = user.plan.name
        log_message(LogLevel.DEBUG, f"GitHub plan: {plan}", indent_level=1)
        return plan
    except GithubException as e:
        log_message(LogLevel.ERROR, f"Failed to get GitHub plan: {e}", indent_level=1)
        return None


def get_github_version(*, github_target):
    try:
        requester = github_target._Github__requester
        headers, data = requester.requestJsonAndCheck("GET", "/meta")
        if "installed_version" in data:
            return data["installed_version"]
        else:
            return False
    except GithubException as e:
        log_message(LogLevel.ERROR, "Failed to get GitHub version: {}", e)
        return None


def github_check_rate_limit(*, github_target, indent_level=0):
    try:
        rate_limit = github_target.get_rate_limit()
        core_rate_limit = rate_limit.core
        # Check if the remaining limit is below a threshold
        percent_remaining = round(
            100 * core_rate_limit.remaining / core_rate_limit.limit
        )
        time_remaining = round(
            (
                core_rate_limit.reset.astimezone(timezone.utc)
                - datetime.now(timezone.utc)
            ).total_seconds()
        )
        log_message(
            LogLevel.DEBUG,
            "GitHub rate limit: {}% remaining, {} seconds until reset",
            percent_remaining,
            time_remaining,
            indent_level=indent_level,
        )
        # backoff if we are below a threshold
        threshold = 30
        if percent_remaining <= threshold:
            sleep_time = (
                time_remaining * (threshold - percent_remaining + 1) / threshold
            )
            # examples of this calculation for threshold=30
            #   percent_remaining = 30, sleep for   3% of the time remaining
            #   percent_remaining = 25, sleep for  20% of the time remaining
            #   percent_remaining = 15, sleep for  53% of the time remaining
            #   percent_remaining = 5,  sleep for  87% of the time remaining
            #   percent_remaining = 2,  sleep for  97% of the time remaining
            #   percent_remaining = 1,  sleep for 100% of the time remaining
            log_message(
                LogLevel.WARNING,
                "Approaching GitHub rate limit. Sleeping for {} seconds.",
                sleep_time,
                indent_level=indent_level,
            )
            time.sleep(sleep_time)

    except GithubException as e:
        log_message(
            LogLevel.CRITICAL, "An error occurred: {}", e, indent_level=indent_level
        )


def github_create_repo(
    *,
    github_target,
    repo_name,
    org_name=None,
    expected_settings={},
    indent_level=0,
    dry_run=False,
):
    try:
        if dry_run:
            log_message(
                LogLevel.INFO,
                (
                    f"[Dry-run] Would create repository '{repo_name}' in organization '{org_name}'"
                    if org_name
                    else f"[Dry-run] Would create user repository '{repo_name}'"
                ),
                indent_level=indent_level,
            )
            return None  # Simulate no repo created
        # use a minimal set of settings to create the repo
        # so make sure that enforce_repo_settings() will be run shortly afterwards
        repo_settings = {
            "name": repo_name,
            "private": expected_settings.get("private", True),
            "auto_init": expected_settings.get("auto_init", False),
        }
        if org_name:
            # Create a repository in the specified organization
            org = github_target.get_organization(org_name)
            new_repo = org.create_repo(**repo_settings)
            log_message(
                LogLevel.INFO,
                f"Repository '{repo_name}' created in organization '{org_name}'",
                indent_level=indent_level,
            )
        else:
            # Create a user repository
            new_repo = github_target.get_user().create_repo(**repo_settings)
            log_message(
                LogLevel.INFO,
                f"User repository '{repo_name}' created for user",
                indent_level=indent_level,
            )

        return new_repo

    except GithubException as e:
        raise Exception("An error occurred while creating repo: {}", e)


def github_enforce_branch_protection(
    *,
    github_repo,
    repo_name,
    repo_owner,
    expected_settings,
    indent_level=0,
    dry_run=False,
):
    """
    Enforce branch protection rules for a GitHub repository.

    Args:
        github_repo (object): The GitHub repository object.
        repo_name (str): The name of the repository.
        repo_owner (str): The owner of the repository.
        expected_settings (dict): The expected settings containing branch protection rules.
        indent_level (int): The indentation level for logging.
        dry_run (bool): If True, simulate the changes without applying them.

    Returns:
        None
    """
    try:
        branch_protection_data = expected_settings.get("branch_protection", None)
        if not branch_protection_data:
            log_message(
                LogLevel.INFO,
                f"No branch protection settings found for repository '{repo_name}'. Skipping branch protection enforcement.",
                indent_level=indent_level,
            )
            return

        branches = branch_protection_data.get("branches", ["main"])
        protections = branch_protection_data.get("protections", {})

        for branch_name in branches:
            log_message(
                LogLevel.INFO,
                f"Enforcing branch protection for branch '{branch_name}' in repository '{repo_name}'.",
                indent_level=indent_level,
            )

            if dry_run:
                log_message(
                    LogLevel.INFO,
                    f"[Dry-run] Would enforce branch protection for branch '{branch_name}' in repository '{repo_name}'.",
                    indent_level=indent_level,
                )
                continue

            try:
                branch = github_repo.get_branch(branch_name)
                log_message(
                    LogLevel.DEBUG,
                    f"Retrieved branch '{branch_name}' for repository '{repo_name}'.",
                    indent_level=indent_level + 1,
                )
            except GithubException as e:
                if e.status == 404:
                    log_message(
                        LogLevel.WARNING,
                        f"Branch '{branch_name}' does not exist in repository '{repo_name}'. Skipping branch protection enforcement.",
                        indent_level=indent_level,
                    )
                    continue
                else:
                    log_message(
                        LogLevel.ERROR,
                        f"Failed to retrieve branch '{branch_name}' in repository '{repo_name}': {e}",
                        indent_level=indent_level,
                    )
                    raise

            # Apply branch protection rules with safe handling for missing elements
            log_message(
                LogLevel.DEBUG,
                f"Applying branch protection rules for branch '{branch_name}' in repository '{repo_name}'.",
                indent_level=indent_level + 1,
            )
            branch.edit_protection(
                enforce_admins=protections.get("enforce_admins", False),
                allow_force_pushes=protections.get("allow_force_pushes", False),
                allow_deletions=protections.get("allow_deletions", False),
                block_creations=protections.get("block_creations", False),
                required_conversation_resolution=protections.get(
                    "required_conversation_resolution", False
                ),
                required_linear_history=protections.get(
                    "required_linear_history", False
                ),
            )
            log_message(
                LogLevel.DEBUG,
                f"Basic branch protection rules applied for branch '{branch_name}' in repository '{repo_name}'.",
                indent_level=indent_level + 1,
            )

            # Set required status checks separately
            required_status_checks = protections.get("required_status_checks", None)
            if required_status_checks:
                log_message(
                    LogLevel.DEBUG,
                    f"Applying required status checks for branch '{branch_name}' in repository '{repo_name}': {required_status_checks}",
                    indent_level=indent_level + 1,
                )
                branch.edit_required_status_checks(
                    contexts=required_status_checks.get("contexts", []),
                    strict=required_status_checks.get("strict", False),
                )

            # Set required pull request reviews separately
            required_pull_request_reviews = protections.get(
                "required_pull_request_reviews", None
            )
            if required_pull_request_reviews:
                log_message(
                    LogLevel.DEBUG,
                    f"Applying required pull request reviews for branch '{branch_name}' in repository '{repo_name}': {required_pull_request_reviews}",
                    indent_level=indent_level + 1,
                )
                branch.edit_required_pull_request_reviews(
                    dismiss_stale_reviews=required_pull_request_reviews.get(
                        "dismiss_stale_reviews", False
                    ),
                    require_code_owner_reviews=required_pull_request_reviews.get(
                        "require_code_owner_reviews", False
                    ),
                    required_approving_review_count=required_pull_request_reviews.get(
                        "required_approving_review_count", 1
                    ),
                )

            log_message(
                LogLevel.INFO,
                f"Branch protection enforced for branch '{branch_name}' in repository '{repo_name}'.",
                indent_level=indent_level,
            )

    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"Failed to enforce branch protection for repository '{repo_name}': {e}",
            indent_level=indent_level,
        )
        raise


def github_enforce_gitignore(
    *,
    github_repo,
    repo_name,
    repo_owner,
    expected_settings,
    indent_level=0,
    dry_run=False,
):
    """
    Enforce the .gitignore configuration for a GitHub repository.

    Args:
        github_repo (object): The GitHub repository object.
        expected_settings (dict): The expected settings containing .gitignore configuration and branches.
        indent_level (int): The indentation level for logging.
    """
    try:
        if dry_run:
            log_message(
                LogLevel.INFO,
                f"[Dry-run] Would enforce .gitignore for repository '{repo_name}'",
                indent_level=indent_level,
            )
            return
        gitignore_data = expected_settings.get("gitignore", None)
        if not gitignore_data:
            log_message(
                LogLevel.INFO,
                f"No .gitignore settings found for repository '{repo_name}'. Skipping .gitignore enforcement.",
                indent_level=indent_level,
            )
            return

        gitignore_config = gitignore_data.get("config")
        gitignore_type = gitignore_data.get("type")
        branches = gitignore_data.get("branches", ["main"])

        log_message(
            LogLevel.INFO,
            f"Enforcing .gitignore for repository '{repo_name}' on branches: {branches}",
            indent_level=indent_level,
        )

        # Use the type provided in the gitignore data
        if gitignore_type == "url":
            # Fetch .gitignore content from URL
            log_message(
                LogLevel.INFO,
                f"Fetching .gitignore content from URL: {gitignore_config}",
                indent_level=indent_level + 1,
            )
            response = requests.get(gitignore_config)
            response.raise_for_status()
            gitignore_content = response.text
        elif gitignore_type == "file":
            # Read .gitignore content from file
            log_message(
                LogLevel.INFO,
                f"Reading .gitignore content from file: {gitignore_config}",
                indent_level=indent_level + 1,
            )
            with open(gitignore_config, "r") as file:
                gitignore_content = file.read()
        elif gitignore_type == "list":
            # Use inline list as .gitignore content
            log_message(
                LogLevel.INFO,
                "Using inline .gitignore content.",
                indent_level=indent_level + 1,
            )
            gitignore_content = "\n".join(gitignore_config)
        else:
            raise ValueError(f"Unsupported .gitignore type: {gitignore_type}")

        # Apply the .gitignore content to the specified branches
        for branch in branches:
            log_message(
                LogLevel.INFO,
                f"Checking .gitignore for branch '{branch}' in repository '{repo_name}'.",
                indent_level=indent_level + 1,
            )
            try:
                contents = github_repo.get_contents(".gitignore", ref=branch)
                current_content = contents.decoded_content.decode("utf-8")
                if current_content != gitignore_content:
                    log_message(
                        LogLevel.INFO,
                        f"Updating .gitignore for branch '{branch}' in repository '{repo_name}'.",
                        indent_level=indent_level + 1,
                    )
                    github_repo.update_file(
                        path=contents.path,
                        message=f"Update .gitignore on branch '{branch}'",
                        content=gitignore_content,
                        sha=contents.sha,
                        branch=branch,
                    )
                else:
                    log_message(
                        LogLevel.INFO,
                        f".gitignore is already up-to-date for branch '{branch}' in repository '{repo_name}'.",
                        indent_level=indent_level + 1,
                    )
            except GithubException as e:
                if e.status == 404:
                    # File does not exist, create it
                    log_message(
                        LogLevel.INFO,
                        f"Creating .gitignore for branch '{branch}' in repository '{repo_name}'.",
                        indent_level=indent_level + 1,
                    )
                    github_repo.create_file(
                        path=".gitignore",
                        message=f"Create .gitignore on branch '{branch}'",
                        content=gitignore_content,
                        branch=branch,
                    )
                else:
                    raise

        log_message(
            LogLevel.INFO,
            f".gitignore enforcement completed for repository '{github_repo.full_name}'.",
            indent_level=indent_level,
        )
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"Failed to enforce .gitignore for repository '{github_repo.full_name}': {e}",
            indent_level=indent_level,
        )
        raise


def github_enforce_repo_settings(
    *,
    github_repo,
    expected_settings,
    reponame,
    repoowner,
    indent_level=0,
    dry_run=False,
):
    try:
        if dry_run:
            log_message(
                LogLevel.INFO,
                f"[Dry-run] Would enforce settings for {repoowner}/{reponame}",
                indent_level=indent_level,
            )
            return True  # Simulate success
        log_message(
            LogLevel.INFO,
            f"Repository settings enforcing for {repoowner}/{reponame}",
            indent_level=indent_level,
        )
        # List of attributes to check
        attributes = [
            "allow_merge_commit",
            "allow_rebase_merge",
            "allow_squash_merge",
            "default_branch",
            "delete_branch_on_merge",
            "has_discussions",
            "has_issues",
            "has_projects",
            "has_wiki",
            "private",
        ]

        # Get current settings dynamically
        current_settings = {
            attr: github_repo.__dict__.get(attr, None)
            for attr in attributes
            if attr in github_repo.__dict__
        }

        # Check if the repository has any branches
        branches = list(github_repo.get_branches())
        if not branches:
            log_message(
                LogLevel.WARNING,
                f"Repository {repoowner}/{reponame} has no branches. Skipping default_branch setting.",
                indent_level=indent_level,
            )
            current_settings.pop("default_branch", None)
            expected_settings.pop("default_branch", None)

        # Determine if settings need to be updated
        update_needed = any(
            current_settings[key] != expected_settings.get(key, current_settings[key])
            for key in current_settings
        )

        if update_needed:
            # Build the arguments for the edit method dynamically
            edit_args = {key: expected_settings.get(key) for key in current_settings}

            github_repo.edit(**edit_args)
            log_message(
                LogLevel.INFO,
                f"Repository settings enforced for {repoowner}/{reponame}",
                indent_level=indent_level,
            )
        else:
            log_message(
                LogLevel.INFO,
                f"Repository settings correct No changes needed for repository settings for {repoowner}/{reponame}",
                indent_level=indent_level,
            )
        return True
    except GithubException as e:
        raise Exception(
            f"Error while enforcing settings for repo {repoowner}/{reponame}: {e}"
        )


def github_enforce_repo_team_permissions(
    *, github_instance, repo_name, expected_repo_data, indent_level=0, dry_run=False
):
    try:
        if dry_run:
            log_message(
                LogLevel.INFO,
                f"[Dry-run] Would enforce team permissions for {repo_name}",
                indent_level=indent_level,
            )
            return  # Simulate no changes
        org_name = expected_repo_data.get("owner")
        log_message(
            LogLevel.INFO,
            f"Team permissions enforcing for {repo_name}",
            indent_level=indent_level,
        )
        # Get the repository object
        repo = github_instance.get_repo(f"{org_name}/{repo_name}")
        # Get the current team permissions from the repository
        current_permissions = {team.slug: team.permission for team in repo.get_teams()}
        # Get the desired team permissions from the repo_data
        desired_permissions = expected_repo_data.get("team_permissions", {})
        # Combine current and expanded desired permissions to ensure all teams are considered
        all_teams = set(current_permissions.keys()).union(desired_permissions.keys())

        # Compare and enforce permissions
        for team in all_teams:
            desired_permission = desired_permissions.get(team)
            current_permission = current_permissions.get(team, {})

            # Determine if an update is needed
            update_needed = False
            if desired_permission is None:
                # Team is not in desired permissions, remove them
                try:
                    repo.remove_from_collaborators(team)
                    log_message(
                        LogLevel.INFO,
                        f"Removed team {team} from {repo_name}",
                        indent_level=indent_level,
                    )
                except GithubException as e:
                    log_message(
                        LogLevel.ERROR,
                        f"Failed to remove team {team} from {repo_name}: {e}",
                        indent_level=indent_level,
                    )
            else:
                if desired_permission == "admin" and not current_permission.get(
                    "admin", False
                ):
                    update_needed = True
                elif desired_permission in [
                    "push",
                    "write",
                ] and not current_permission.get("push", False):
                    update_needed = True
                elif desired_permission in [
                    "pull",
                    "read",
                ] and not current_permission.get("pull", False):
                    update_needed = True

                # Update the team's permission if needed
                if update_needed:
                    try:
                        # Check if the team exists
                        org = github_instance.get_organization(org_name)
                        org.get_team_by_slug(team)
                    except GithubException as e:
                        log_message(
                            LogLevel.ERROR,
                            f"Team {team} requested as a collaborator to {repo_name}: team does not exist",
                            indent_level=indent_level + 1,
                        )
                        continue

                    try:
                        # If the team exists, add them as a collaborator
                        repo.add_to_collaborators(team, permission=desired_permission)
                        log_message(
                            LogLevel.INFO,
                            f"Updated team {team}'s permission to {desired_permission} in {repo_name}",
                            indent_level=indent_level + 1,
                        )
                    except GithubException as e:
                        log_message(
                            LogLevel.ERROR,
                            f"Failed to add team {team} as a collaborator to {repo_name}: {e}",
                            indent_level=indent_level + 1,
                        )
                        continue

        log_message(
            LogLevel.INFO,
            f"Team permissions enforced for repository {repo_name}",
            indent_level=indent_level,
        )
    except GithubException as e:
        log_message(
            LogLevel.ERROR,
            f"Error while enforcing team permissions in repository {repo_name}: {e}",
            indent_level=indent_level,
        )


def github_enforce_repo_user_permissions(
    *, github_instance, repo_name, expected_repo_data, indent_level=0, dry_run=False
):
    try:
        if dry_run:
            log_message(
                LogLevel.INFO,
                f"[Dry-run] Would enforce user permissions for {repo_name}",
                indent_level=indent_level,
            )
            return  # Simulate no changes
        org_name = expected_repo_data.get("owner")
        log_message(
            LogLevel.INFO,
            f"User permissions enforcing for {repo_name}",
            indent_level=indent_level,
        )
        # Get the repository object
        repo = github_instance.get_repo(f"{org_name}/{repo_name}")
        # Get the current user permissions from the repository, only consider direct collaborators
        current_permissions = {
            collaborator.login: collaborator.permissions
            for collaborator in repo.get_collaborators(affiliation="direct")
        }
        # Get the desired user permissions from the repo_data
        desired_permissions = expected_repo_data.get("user_permissions", {})
        # Combine current and expanded desired permissions to ensure all users are considered
        all_users = set(current_permissions.keys()).union(desired_permissions.keys())

        # Compare and enforce permissions
        for user in all_users:
            desired_permission = desired_permissions.get(user)
            current_permission = current_permissions.get(user, {})
            # Determine if an update is needed
            update_needed = False
            if desired_permission is None:
                # User is not in desired permissions, remove them
                repo.remove_from_collaborators(user)
                log_message(
                    LogLevel.INFO,
                    f"Removed {user} from {repo_name}",
                    indent_level=indent_level,
                )
            else:
                if desired_permission == "admin" and not current_permission.get(
                    "admin", False
                ):
                    update_needed = True
                elif desired_permission in [
                    "push",
                    "write",
                ] and not current_permission.get("push", False):
                    update_needed = True
                elif desired_permission in [
                    "pull",
                    "read",
                ] and not current_permission.get("pull", False):
                    update_needed = True

                # Update the user's permission if needed
                if update_needed:
                    try:
                        # Check if the user exists
                        github_instance.get_user(user)
                    except GithubException as e:
                        log_message(
                            LogLevel.ERROR,
                            f"User {user} requested as a collaborator to {repo_name} does not exist",
                            indent_level=indent_level + 1,
                        )
                        continue

                    try:
                        # If the user exists, add them as a collaborator
                        repo.add_to_collaborators(user, permission=desired_permission)
                        log_message(
                            LogLevel.INFO,
                            f"Updated {user}'s permission to {desired_permission} in {repo_name}",
                            indent_level=indent_level + 1,
                        )
                    except GithubException as e:
                        log_message(
                            LogLevel.ERROR,
                            f"Failed to add {user} as a collaborator to {repo_name}: {e}",
                            indent_level=indent_level + 1,
                        )
                        continue

        log_message(
            LogLevel.INFO,
            f"User permissions enforced for repository {repo_name}",
            indent_level=indent_level,
        )

    except GithubException as e:
        log_message(
            LogLevel.ERROR,
            f"Error while enforcing user permissions in repository {repo_name}: {e}",
            indent_level=indent_level,
        )


def github_enforce_repo_webhooks(
    *, github_repo, expected_settings, indent_level=0, dry_run=False
):
    """
    Enforce the desired webhooks on a repository.

    Args:
        github_repo: The repository object.
        expected_settings: A list of desired webhook configurations.
        indent_level: The indentation level for logging.
        dry_run: If True, simulate the changes without applying them.

    Returns:
        None
    """
    try:
        if dry_run:
            log_message(
                LogLevel.INFO,
                f"[Dry-run] Would enforce webhooks for {github_repo.full_name}",
                indent_level=indent_level,
            )
            return  # Simulate no changes

        log_message(
            LogLevel.INFO,
            f"Enforcing webhooks for {github_repo.full_name}",
            indent_level=indent_level,
        )

        # Check if there are no webhooks in the expected settings
        if not expected_settings.get("webhooks"):
            log_message(
                LogLevel.INFO,
                f"No webhooks specified in expected settings for {github_repo.full_name}",
                indent_level=indent_level,
            )
            return

        # Compare and enforce webhooks
        for desired_webhook in expected_settings["webhooks"]:
            create_or_update_github_webhook(
                github_repo=github_repo,
                webhook_config=desired_webhook,
                indent_level=indent_level + 1,
            )

        log_message(
            LogLevel.INFO,
            f"Webhooks enforced for repository {github_repo.full_name}",
            indent_level=indent_level,
        )
    except GithubException as e:
        log_message(
            LogLevel.ERROR,
            f"Error while enforcing webhooks in repository {github_repo.full_name}: {e}",
            indent_level=indent_level,
        )


def github_process_target_repo(
    *,
    github_target,
    github_user_login,
    repo_name,
    expected_repo_data,
    indent_level=0,
    dry_run=False,
):
    repo_owner = expected_repo_data.get("owner")
    if not repo_owner:
        return False
    # Check if the repo exists in the destination. Note that this handles exceptions and returns a status, as well as the repo object if it exists
    status, github_target_repo = github_repo_exists(
        github_target=github_target,
        repo_name=repo_name,
        repo_owner=repo_owner,
        indent_level=indent_level,
    )
    if status:
        if github_target_repo is not None:
            # Repo exists and is readable
            if github_repo_admin_permissions(
                github_repo=github_target_repo,
                github_user_login=github_user_login,
                indent_level=indent_level + 1,
            ):
                # Repo exists and is readable and we have admin permissions
                log_message(
                    LogLevel.INFO,
                    f"Current user has admin permissions on target repo {repo_owner}/{repo_name}",
                    indent_level=indent_level,
                )
        else:
            # Repo exists but is not readable
            log_message(
                LogLevel.WARNING,
                f"Repo {repo_owner}/{repo_name} exists but is not readable",
                indent_level=indent_level,
            )
            return False
    else:
        # Repo does not exist
        if expected_repo_data["create_repo"]:
            log_message(
                LogLevel.INFO,
                f"Creating target repo {repo_owner}/{repo_name}",
                indent_level=indent_level,
            )
            github_target_repo = github_create_repo(
                github_target=github_target,
                repo_name=repo_name,
                org_name=repo_owner,
                expected_settings=expected_repo_data,
                indent_level=indent_level + 1,
                dry_run=dry_run,
            )
            if not github_target_repo:
                log_message(
                    LogLevel.ERROR,
                    f"Failed to create target repo {repo_owner}/{repo_name}",
                    indent_level=1,
                )
                return False
        else:
            log_message(
                LogLevel.WARNING,
                f"Repo {repo_owner}/{repo_name} does not exist, but we are not asked to create",
                indent_level=1,
            )
            # is this inconsistency an error? It is a misconfiguration, but not necessarily an error in the program
            return True

    # if we get to here, we have a target repo object

    # Check the repo owner type and plan so we can modify behaviour here as a result
    type, plan = get_github_repo_owner_type_plan(
        github_target=github_target, repo_owner=repo_owner, repo_name=repo_name
    )
    log_message(
        LogLevel.DEBUG,
        f"Repo owner type: {type}, plan: {plan}",
        indent_level=indent_level,
    )

    log_message(LogLevel.DEBUG, f"Have target repo object", indent_level=1)
    if expected_repo_data["enforce_repo_settings"]:
        github_enforce_repo_settings(
            github_repo=github_target_repo,
            expected_settings=expected_repo_data["repo_settings"],
            reponame=repo_name,
            repoowner=repo_owner,
            indent_level=indent_level + 1,
            dry_run=dry_run,
        )
        github_enforce_repo_user_permissions(
            github_instance=github_target,
            repo_name=repo_name,
            expected_repo_data=expected_repo_data,
            indent_level=indent_level + 1,
            dry_run=dry_run,
        )
        github_enforce_repo_team_permissions(
            github_instance=github_target,
            repo_name=repo_name,
            expected_repo_data=expected_repo_data,
            indent_level=indent_level + 1,
            dry_run=dry_run,
        )
        github_enforce_repo_webhooks(
            github_repo=github_target_repo,
            expected_settings=expected_repo_data,
            indent_level=indent_level + 1,
            dry_run=dry_run,
        )
        github_enforce_gitignore(
            github_repo=github_target_repo,
            repo_name=repo_name,
            repo_owner=repo_owner,
            expected_settings=expected_repo_data,
            indent_level=indent_level + 1,
            dry_run=dry_run,
        )
        github_enforce_branch_protection(
            github_repo=github_target_repo,
            repo_name=repo_name,
            repo_owner=repo_owner,
            expected_settings=expected_repo_data,
            indent_level=indent_level + 1,
            dry_run=dry_run,
        )
    return True


def github_repo_admin_permissions(
    *, github_repo, github_user_login=None, indent_level=0
):
    try:
        if not github_user_login:
            raise ValueError("Internal error: No GitHub user login provided")
        permissions = github_repo.get_collaborator_permission(github_user_login)
        if permissions == "admin":
            log_message(
                LogLevel.DEBUG,
                f"Current user has admin permissions on repo",
                indent_level=indent_level,
            )
            return True
        else:
            log_message(
                LogLevel.DEBUG,
                f"Current user missing admin permissions on repo",
                indent_level=indent_level,
            )
            return False
    except GithubException as e:
        raise ("An error occurred checking admin permissions on repo: {}", e)


def github_repo_exists(*, github_target, repo_name, repo_owner, indent_level=0):
    try:
        grepo = github_target.get_repo(f"{repo_owner}/{repo_name}")
        log_message(
            LogLevel.DEBUG,
            "Repo exists in target and is readable",
            indent_level=indent_level,
        )
        return True, grepo
    except GithubException as e:
        if e.status == 403:
            log_message(
                LogLevel.DEBUG,
                "Repo exists in target but is not readable",
                indent_level=indent_level,
            )
            return True, None
        elif e.status == 404:
            log_message(
                LogLevel.DEBUG,
                "Repo does not exist in target",
                indent_level=indent_level,
            )
            return False, None
        else:
            raise Exception(
                f"An error occurred checking if repo {repo_owner}/{repo_name} exists: {e}"
            )


def transform_github_webhook_to_config(webhook):
    """
    Transform a webhook object into the JSON format expected by create_or_update_webhook.

    Args:
        webhook: A webhook object returned by the GitHub API.

    Returns:
        A dictionary representing the webhook configuration.
    """
    try:
        config = {
            "url": webhook.config.get("url"),
            "events": webhook.events,
            "secret": webhook.config.get("secret"),
            "content_type": webhook.config.get("content_type", "json"),
            "insecure_ssl": webhook.config.get("insecure_ssl", "0"),
            "active": webhook.active,
        }
        return config
    except AttributeError as e:
        raise ValueError(f"Invalid webhook object: {e}")


def update_file_in_repo(
    *, repo, file_path, local_file_path, commit_message, branch, dry_run=False
):
    try:
        # Read the local file content
        with open(local_file_path, "r") as file:
            local_content = file.read()

        # Check if the file exists in the repository
        try:
            contents = repo.get_contents(file_path, ref=branch)
            repo_content = contents.decoded_content.decode("utf-8")
            # If the file exists and is different, update it
            if local_content != repo_content:
                if dry_run:
                    log_message(
                        LogLevel.INFO,
                        f"[Dry-run] Would update file '{file_path}' in repository '{repo.full_name}'",
                    )
                    return
                else:
                    repo.update_file(
                        contents.path,
                        commit_message,
                        local_content,
                        contents.sha,
                        branch=branch,
                    )
                    log_message(
                        LogLevel.INFO,
                        "Updated file '{}' in repository '{}'",
                        file_path,
                        repo.full_name,
                    )
            else:
                log_message(
                    LogLevel.INFO,
                    "File '{}' is already up to date in repository '{}'",
                    file_path,
                    repo.full_name,
                )
        except GithubException as e:
            if e.status == 404:
                # File does not exist, create it
                if dry_run:
                    log_message(
                        LogLevel.INFO,
                        f"[Dry-run] Would create file '{file_path}' in repository '{repo.full_name}'",
                    )
                    return
                else:
                    repo.create_file(
                        file_path, commit_message, local_content, branch=branch
                    )
                    log_message(
                        LogLevel.INFO,
                        "Created file '{}' in repository '{}'",
                        file_path,
                        repo.full_name,
                    )
            else:
                # Handle other exceptions
                raise
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            "Failed to update file in repository '{}': {}",
            repo.full_name,
            e,
        )
