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

import csv
import json
import os
from gitrepomanager.common.logging_utils import log_message
from gitrepomanager.common.logging_utils import LogLevel


def csv_file_to_json_file(csv_file_path, json_file_path):
    # This is a special case of converting the old format CSV repo config file to a JSON file
    # with field manipulation in transit to the new format

    try:
        # create data structure
        data = {}

        # write these settings into the JSON file
        data["settings"] = {}
        data["settings"] = {
            "target_repo_type": "github",
            "source_repo_type": "subversion",
            "log_level": "info",
        }
        # write defaults to JSON file
        # these mostly come from the old script code variables etc.
        data["defaults"] = {}
        data["defaults"]["repo_settings"] = {}
        data["defaults"]["repo_settings"]["standard"] = {
            "allow_merge_commit": True,
            "allow_rebase_merge": False,
            "allow_squash_merge": True,
            "default_branch": "main",
            "delete_branch_on_merge": True,
            "has_discussions": False,
            "has_issues": False,
            "has_projects": False,
            "has_wiki": False,
            "private": True,
        }
        data["defaults"][
            "subversion_ignore_paths"
        ] = ".*(\\.jar|\\.class|\\.log|\\.xls|\\.xlsx|\\.zip|\\.doc|\\.docx|\\.pptx|\\.tar|\\.rar|ML-Document-Command-readyapi-project\\.xml|Document-Upload-readyapi-project-AW\\.xml)$"
        data["defaults"]["team_permissions"] = {}
        data["defaults"]["team_permissions"]["standard"] = {
            "agile-development": "push",
            "devops": "admin",
            "EPAM": "push",
        }
        data["defaults"]["team_permissions"]["iacconfig"] = {
            "agile-development": "push",
            "devops": "admin",
            "EPAM": "push",
            "gitops": "pull",
            "eu-pd-gitopsprodapprovers": "push",
        }
        data["defaults"]["team_permissions"]["devops"] = {
            "devops": "admin",
        }
        data["defaults"]["user_permissions"] = {}
        data["defaults"]["user_permissions"]["iacconfig"] = {
            "argocd-deployer-uk-p": "read",
        }
        data["defaults"]["webhooks"]["standard"] = {
            "url": "https://jenkins.de-cbj.ekspd.aws.travp.net/teams-uk-software-engineering/github-webhook/",
            "events": [
                "push",
                "pull_request",
                "pull_request_review",
                "pull_request_review_comment",
            ],
            "content_type": "form",
            "insecure_ssl": "0",
        }
        data["defaults"]["webhooks"]["pronly"] = {
            "url": "https://jenkins.de-cbj.ekspd.aws.travp.net/teams-uk-software-engineering/github-webhook/",
            "events": [
                "pull_request",
                "pull_request_review",
                "pull_request_review_comment",
            ],
            "content_type": "form",
            "insecure_ssl": "0",
        }
        data["defaults"]["gitignore"]["standard"] = {
            "config": "../../master.gitignore",
            "branches": ["main"],
        }
        data["defaults"]["branch_protection"]["mainonlyallowpush"] = {
            "branches": ["main"],
            "protections": {
                "required_status_checks": None,
                "enforce_admins": True,
                "required_pull_request_reviews": {
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": False,
                    "required_approving_review_count": 1,
                    "require_last_push_approval": False,
                    "bypass_pull_request_allowances": {
                        "users": ["N86D49", "TRVEU-JENKINS-SVN"],
                        "teams": [],
                    },
                },
                "restrictions": {
                    "users": [],
                    "teams": ["devops", "epam", "agile-development"],
                },
                "block_creations": False,
                "allow_force_pushes": False,
                "allow_deletions": False,
                "lock branch": False,
                "required_conversation_resolution": False,
                "required_linear_history": False,
                "required_signatures": False,
            },
        }
        data["defaults"]["branch_protection"]["epam"] = {
            "branches": ["main"],
            "protections": {
                "required_status_checks": None,
                "enforce_admins": True,
                "required_pull_request_reviews": {
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": False,
                    "required_approving_review_count": 1,
                    "require_last_push_approval": False,
                    "bypass_pull_request_allowances": {
                        "users": ["N86D48", "N86D49", "N86D4F", "N86D71", "TRVEU-JENKINS-SVN"],
                        "teams": [],
                    },
                },
                "restrictions": {
                    "users": [],
                    "teams": [
                        "devops",
                        "epam",
                    ],
                },
                "block_creations": False,
                "allow_force_pushes": False,
                "allow_deletions": False,
                "lock branch": False,
                "required_conversation_resolution": False,
                "required_linear_history": False,
                "required_signatures": False,
            },
        }
        data["defaults"]["branch_protection"]["iacconfig"] = {
            "branches": ["main", "release-dev", "release-test", "release-mo"],
            "protections": {
                "required_status_checks": None,
                "enforce_admins": True,
                "required_pull_request_reviews": None,
                "restrictions": {
                    "users": [],
                    "teams": [
                        "devops",
                        "epam",
                    ],
                },
                "block_creations": False,
                "allow_force_pushes": False,
                "allow_deletions": False,
                "lock branch": False,
                "required_conversation_resolution": False,
                "required_linear_history": False,
                "required_signatures": False,
            },
        }
        data["repos"] = {}

        # Open the CSV file for reading
        if not os.path.exists(csv_file_path):
            raise FileNotFoundError(f"Error: The file {csv_file_path} was not found.")

        with open(csv_file_path, mode="r") as csv_file:
            csv_reader = csv.DictReader(csv_file)

            # Open the JSON file for writing
            with open(json_file_path, mode="w") as json_file:

                for row in csv_reader:
                    gitreponame = row.get("GitRepoName")

                    data["repos"][gitreponame] = {}
                    data["repos"][gitreponame]["owner"] = row.get("GitRepoOwner")
                    # Add repo_settings to each repo record
                    # these were the defaults in the old script
                    # aim is to create a minimalist JSON file where absence of a field means don't do it (eg sync_from_source)
                    if row.get("RepoSettings", "").strip().lower() == "yes":
                        data["repos"][gitreponame]["enforce_repo_settings"] = True
                        data["repos"][gitreponame]["repo_settings"] = {}
                        data["repos"][gitreponame]["repo_settings"][
                            "use_default"
                        ] = "standard"
                        if row.get("Wiki", "").strip().lower() == "yes":
                            data["repos"][gitreponame]["repo_settings"][
                                "has_wiki"
                            ] = True
                    else:
                        data["repos"][gitreponame]["enforce_repo_settings"] = False
                    data["repos"][gitreponame]["application"] = row.get(
                        "App", "unknown"
                    )
                    data["repos"][gitreponame]["create_repo"] = (
                        True
                        if row.get("CreateRepo", "").strip().lower() == "yes"
                        else False
                    )
                    # old data file has these combinations in:
                    # 2025-01-16 23:14:40 - INFO     sync_from_source: False, final_sync: False, deletemainsvn: False -> Total: 325
                    # 2025-01-16 23:14:40 - INFO     sync_from_source: False, final_sync: True, deletemainsvn: True -> Total: 182
                    # so we can ignore the final_sync and deletemainsvn fields as their work is complete! :)
                    #
                    # if row.get('SyncSVN', '').strip().lower() == 'yes' or row.get('FinalSync', '').strip().lower() == 'yes' or row.get('FinalSync','').strip().lower() == 'deletemainsvn':
                    #     data['repos'][gitreponame]['sync_from_source'] = True if row.get('SyncSVN', '').strip().lower() == 'yes' else False
                    #     if row.get('FinalSync', '').strip().lower() == 'yes':
                    #         data['repos'][gitreponame]['final_sync'] = True
                    #     elif row.get('FinalSync', '').strip().lower() == 'deletemainsvn':
                    #         data['repos'][gitreponame]['final_sync'] = True
                    #         data['repos'][gitreponame]['deletemainsvn'] = True
                    #     else:
                    #         data['repos'][gitreponame]['final_sync'] = False
                    if row.get("SyncSVN", "").strip().lower() == "yes":
                        data["repos"][gitreponame]["source_repo"] = (
                            row.get("SVN repository")
                            if row.get("SVN repository") != "notapplicable"
                            else None
                        )
                        data["repos"][gitreponame]["subversion_revision"] = (
                            row.get("svnrevision")
                            if row.get("svnrevision") != "HEAD"
                            else None
                        )
                    topics = row.get("Topics", "").strip()
                    if topics:
                        data["repos"][gitreponame]["repo_topics"] = topics.split("|")
                    # team permissions do not have a default in the old script
                    teamperms = row.get("TeamPerms", "").strip()
                    if teamperms:
                        team_permissions = {
                            team.split("=")[0]: (
                                team.split("=")[1] if "=" in team else ""
                            )
                            for team in teamperms.split("|")
                        }
                        data["repos"][gitreponame][
                            "team_permissions"
                        ] = team_permissions
                    userperms = row.get("UserPerms", "").strip()
                    if userperms:
                        user_permissions = {
                            user.split("=")[0]: (
                                ""
                                if user.split("=")[0] == "iacconfig"
                                else (user.split("=")[1] if "=" in user else "admin")
                            )
                            for user in userperms.split("|")
                        }
                        data["repos"][gitreponame][
                            "user_permissions"
                        ] = user_permissions
                    if row.get("WebHook", "").strip().lower() == "standard":
                        data["repos"][gitreponame]["webhooks"] = {"standard": ""}
                    elif row.get("WebHook", "").strip().lower() == "pronly":
                        data["repos"][gitreponame]["webhooks"] = {"pronly": ""}
                    # we choose to ignore the other old script's webhook settings
                    if row.get("GitIgnore", "").strip().lower() == "yes":
                        data["repos"][gitreponame]["gitignore"] = {"standard": ""}

                json.dump(data, json_file, indent=4)
                log_message(
                    LogLevel.INFO,
                    f"JSON file created successfully: {json_file_path}",
                    indent_level=1,
                )

    # Still to be done:

    # TODO: PrePostMigration was a flag to alter some permissions.  We should find a way to not need this in the new config file
    # TODO: GitIgnore
    # TODO: branchprotect
    # TODO: PermsDeleteUnexpected - maybe this is duplicated by enforce_repo_settings?

    except FileNotFoundError:
        raise Exception(f"Error: The file {csv_file_path} was not found.")
    except csv.Error as e:
        raise Exception(f"Error reading CSV file: {e}")
    except IOError as e:
        raise Exception(f"Error writing to JSON file: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred: {e}")


def get_expected_repo_data(repo_config_data, default_config_data, indent_level=0):
    # Get the default repo settings specified for this repo
    expected_repo_data = {}
    expected_repo_data["repo_settings"] = {}
    if (
        "repo_settings" in repo_config_data
        and "use_default" in repo_config_data["repo_settings"]
    ):
        if repo_config_data["repo_settings"]["use_default"].lower() != "none":
            expected_repo_data["repo_settings"] = default_config_data["repo_settings"][
                repo_config_data["repo_settings"]["use_default"]
            ]
    else:
        log_message(
            LogLevel.ERROR,
            "Repo settings enforced but no default repo settings found, is this intentional? Set ['repo_settings']['use_default']='none' if so.",
            indent_level=indent_level,
        )
        return None

    # Iterate over any other keys in repo['repo_settings'] and use those to set values in expected_repo_settings
    for key, value in repo_config_data.get("repo_settings", {}).items():
        if key != "use_default":
            expected_repo_data["repo_settings"][key] = value
    for key, value in repo_config_data.items():
        if key == "repo_settings":
            for key2, value2 in repo_config_data.get("repo_settings", {}).items():
                if key2 != "use_default":
                    expected_repo_data["repo_settings"][key2] = value2
        elif key == "user_permissions":
            # Get the desired user permissions from the repo_data
            desired_user_permissions = repo_config_data.get("user_permissions", {})
            # Get the default user permissions from the repo_data
            default_user_permissions = default_config_data.get("user_permissions", {})
            # Expand permissions for users with an empty string as their desired permission
            expanded_user_permissions = {}
            for user, permission in desired_user_permissions.items():
                if permission == "":
                    expanded_user_permissions.update(
                        default_user_permissions.get(user, {})
                    )
                else:
                    expanded_user_permissions[user] = permission
            expected_repo_data["user_permissions"] = expanded_user_permissions
        elif key == "team_permissions":
            # Get the desired team permissions from the repo_data
            desired_team_permissions = repo_config_data.get("team_permissions", {})
            # Get the default team permissions from the repo_data
            default_team_permissions = default_config_data.get("team_permissions", {})
            # Expand permissions for teams with an empty string as their desired permission
            expanded_team_permissions = {}
            for team, permission in desired_team_permissions.items():
                if permission == "":
                    expanded_team_permissions.update(
                        default_team_permissions.get(team, {})
                    )
                else:
                    expanded_team_permissions[team] = permission
            expected_repo_data["team_permissions"] = expanded_team_permissions
        elif key == "webhooks":
            # Get the desired webhook settings from the repo_data
            desired_webhook_settings = repo_config_data.get("webhooks", {})
            # Get the default webhook settings from the repo_data
            default_webhook_settings = default_config_data.get("webhooks", {})
            # Expand permissions for webhooks with an empty string as their desired permission
            expanded_webhook_settings = []
            for webhook_name, webhook_config in desired_webhook_settings.items():
                if not webhook_config:
                    # Use default webhook settings if desired config is empty
                    default_config = default_webhook_settings.get(webhook_name, {})
                    if default_config:
                        expanded_webhook_settings.append(default_config)
                else:
                    expanded_webhook_settings.append(webhook_config)

            expected_repo_data["webhooks"] = expanded_webhook_settings
        elif key == "gitignore":
            # Get the desired gitignore settings from the repo_data
            desired_gitignore_settings = repo_config_data.get("gitignore", {})
            # Log a warning if there is more than one entry in desired_gitignore_settings
            if len(desired_gitignore_settings) > 1:
                log_message(
                    LogLevel.WARNING,
                    "Warning: More than one entry found in desired_gitignore_settings.",
                    indent_level=indent_level,
                )
            else:
                # Get the default gitignore settings from the repo_data
                default_gitignore_settings = default_config_data.get("gitignore", {})
                # Expand permissions for the single entry in desired_gitignore_settings
                gitignore_name, gitignore_data = next(
                    iter(desired_gitignore_settings.items()), (None, None)
                )
                if gitignore_name:
                    if not gitignore_data:
                        # Use default gitignore settings if desired config is empty
                        gitignore_data = default_gitignore_settings.get(
                            gitignore_name, {}
                        )

                    # Extract config and branches
                    gitignore_config = gitignore_data.get("config")
                    gitignore_branches = gitignore_data.get("branches", ["main"])

                    # Test the type of the gitignore_config
                    if isinstance(gitignore_config, str):
                        if gitignore_config.startswith(
                            "http://"
                        ) or gitignore_config.startswith("https://"):
                            gitignore_config_type = "url"
                        else:
                            gitignore_config_type = "file"
                    elif isinstance(gitignore_config, list):
                        gitignore_config_type = "list"
                    else:
                        log_message(
                            LogLevel.WARNING,
                            "Gitignore config type is unrecognized.",
                            indent_level=indent_level,
                        )
                        gitignore_config_type = "unknown"

                expected_repo_data["gitignore"] = {
                    "type": gitignore_config_type,
                    "config": gitignore_config,
                    "branches": gitignore_branches,
                }
        elif key == "branch_protection":
            # Get the desired branch protection settings from the repo_data
            desired_branch_protection_settings = repo_config_data.get(
                "branch_protection", {}
            )
            # Log a warning if there is more than one entry in desired_branch_protection_settings
            if len(desired_branch_protection_settings) > 1:
                log_message(
                    LogLevel.WARNING,
                    "Warning: More than one entry found for branch protection settings in repo config.",
                    indent_level=indent_level,
                )
            else:
                # Get the default branch protection settings from the repo_data
                default_branch_protection_settings = default_config_data.get(
                    "branch_protection", {}
                )
                # Expand permissions for the single entry in desired_branch_protection_settings
                branch_protection_name, branch_protection_data = next(
                    iter(desired_branch_protection_settings.items()), (None, None)
                )
                if branch_protection_name:
                    if not branch_protection_data:
                        # Use default branch protection settings if desired config is empty
                        branch_protection_data = default_branch_protection_settings.get(
                            branch_protection_name, {}
                        )

                    # Extract branches and protection rules
                    branch_protection_branches = branch_protection_data.get(
                        "branches", ["main"]
                    )
                    branch_protection_rules = branch_protection_data.get(
                        "protections", {}
                    )

                    # Validate the type of branch_protection_rules
                    if not isinstance(branch_protection_rules, dict):
                        log_message(
                            LogLevel.WARNING,
                            "Branch protection rules type is unrecognized.",
                            indent_level=indent_level,
                        )
                        branch_protection_rules = {}

                expected_repo_data["branch_protection"] = {
                    "branches": branch_protection_branches,
                    "protections": branch_protection_rules,
                }
        else:
            expected_repo_data[key] = value

    return expected_repo_data


def load_config_from_file(config_file, indent_level=0):
    try:
        log_message(
            LogLevel.INFO,
            f"Reading configuration from file: {config_file}",
            indent_level=indent_level,
        )
        with open(config_file, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        raise Exception(f"File not found: {config_file}")
    except json.JSONDecodeError as e:
        raise Exception(f"Error parsing JSON from file {config_file}: {e}")
    except Exception as e:
        raise Exception(
            f"An unexpected error occurred while reading file {config_file}: {e}"
        )


def make_full_path(directory, file):
    # Determine the full path to the script config file
    if os.path.isabs(file):
        return directory
    else:
        return os.path.join(directory, file)


def read_repo_config_data(repo_config_file, indent_level=0):
    config_data = load_config_from_file(repo_config_file)
    if not config_data:
        raise Exception(
            f"No configuration data found - tried using file {repo_config_file}"
        )
    # Extract repos and defaults from config_data
    if "repos" in config_data:
        repo_config_data = config_data["repos"]
    else:
        raise Exception(
            f"No repository configuration data found in file {repo_config_file}"
        )
    if "defaults" in config_data:
        default_config_data = config_data["defaults"]
    else:
        raise Exception(
            f"No defaults configuration data found in file {repo_config_file}"
        )
    return repo_config_data, default_config_data


def temp_convert_csv_repo_config_file(repo_config_file_path, indent_level=0):
    # temporary conversion from old CSV format to new JSON format
    if repo_config_file_path.lower().endswith(".csv"):
        log_message(
            LogLevel.INFO,
            "Converting csv repo config file to temporary json repo config file.",
            indent_level=indent_level,
        )
        repo_config_file_basename = os.path.splitext(repo_config_file_path)[0]
        repo_json_file_path = repo_config_file_basename + ".json"
        csv_file_to_json_file(repo_config_file_path, repo_json_file_path)
        return repo_json_file_path
    else:
        return repo_config_file_path
