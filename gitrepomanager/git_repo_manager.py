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

import argparse
import os
import sys
import traceback
from datetime import datetime
from enum import Enum
from github import Github
from pathlib import Path

# Add the parent directory to the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gitrepomanager.common.args_utils import AlphanumericAction
from gitrepomanager.common.args_utils import parse_arguments
from gitrepomanager.common.cmd_utils import create_unique_temp_directory
from gitrepomanager.common.git_utils import set_global_git_defaults
from gitrepomanager.common.github_utils import authenticate_to_github
from gitrepomanager.common.github_utils import get_github_info
from gitrepomanager.common.github_utils import get_github_repo_url
from gitrepomanager.common.github_utils import github_check_rate_limit
from gitrepomanager.common.github_utils import github_process_target_repo
from gitrepomanager.common.logging_utils import configure_logging
from gitrepomanager.common.logging_utils import log_message
from gitrepomanager.common.logging_utils import LogLevel
from gitrepomanager.common.repo_config_file_ops import get_expected_repo_data
from gitrepomanager.common.repo_config_file_ops import make_full_path
from gitrepomanager.common.repo_config_file_ops import read_repo_config_data
from gitrepomanager.common.repo_config_file_ops import temp_convert_csv_repo_config_file
from gitrepomanager.common.svn_utils import process_svn_source_repo
from gitrepomanager.version import __version__


def is_running_under_jenkins():
    if "JENKINS_HOME" in os.environ:
        return True
    return False


def main():
    try:
        # Record the start time of the script
        start_time = datetime.now()
        unique_temp_path = create_unique_temp_directory()
        script_name = os.path.splitext(os.path.basename(__file__))[0]

        # Configure logging
        # starts at info level, but can be overridden by command line arguments
        configure_logging(
            start_time=start_time,
            log_to_file=False,
            log_to_console=True,
            log_level=LogLevel.INFO,
        )

        parser = argparse.ArgumentParser(
            description=(
                "Git Repository Manager"
                " - Manage configuration of Git repositories as code from a JSON config file."
                " Also optionally migrate code between different types of git repositories."
            ),
            epilog="For more information, see https://github.com/epam/gitrepomanager",
        )

        # Notes:
        # 1) do not use default settings in add_argument, as we want to know if the user has set them or not.
        #    This leaves unset arguments as None.
        # 2) Settings in repo config file are overridden by script config file, which are overridden by command line arguments.
        # 3) Note that log-level has special handling to ensure the log_message function is set up by default to INFO,
        #    and updated as soon as possible to the level requested by the user.
        parser.add_argument(
            "--config-directory",
            type=str,
            default=os.path.dirname(__file__),
            help="Config directory. Defaults to same directory as script.",
            action=AlphanumericAction,
            max_length=80,
        )
        parser.add_argument(
            "--filter-application",
            "-a",
            type=str,
            help="Filter application to work on. Does not support wildcards.",
            action=AlphanumericAction,
            max_length=30,
        )
        parser.add_argument(
            "--filter-repo",
            "-s",
            type=str,
            help="Filter repo to work on. Should be the unqualified name of the repo only. Does not support wildcards.",
            action=AlphanumericAction,
            max_length=30,
        )
        parser.add_argument(
            "--github-org-to-scan",
            type=str,
            help="GitHub Organization to scan for unmanaged repos.",
            action=AlphanumericAction,
            max_length=30,
        )
        parser.add_argument(
            "--log-level",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            help="Set the logging level. Defaults to INFO.",
            action=AlphanumericAction,
            max_length=10,
        )
        parser.add_argument(
            "--max-file-size",
            type=int,
            default=48,
            help="Set the max file size before we filter out before commit. Defaults to 48. Unit is MB.",
            action=AlphanumericAction,
            max_length=6,
        )
        parser.add_argument(
            "--repo-config-file",
            type=str,
            help="Repo config file.",
            action=AlphanumericAction,
        )
        parser.add_argument(
            "--script-config-file",
            type=str,
            nargs="?",
            const="config.json",
            help="Path to json config file for this script (as an alternative to, and overrides command line arguments). Defaults to config.json.",
            action=AlphanumericAction,
            max_length=80,
        )
        parser.add_argument(
            "--script-name",
            type=str,
            default=script_name,
            help="Name of the script, used in some log messages and default working directory path. Defaults to the name of this module without the .py ending.",
            action=AlphanumericAction,
            max_length=30,
        )
        parser.add_argument(
            "--source-repo-type",
            choices=["subversion", "gitlab", "github"],
            nargs="?",
            help="Source repository (svn, gitlab, github,git). Omit for none.",
            action=AlphanumericAction,
            max_length=20,
        )
        parser.add_argument(
            "--subversion-repo-persistent-storage",
            type=str,
            help="Persistent storage to use when keeping local copy of subversion repos.",
            action=AlphanumericAction,
        )
        parser.add_argument(
            "--target-dry-run",
            action="store_true",
            help="Simulate the operations without making any changes to target repo.",
        )
        parser.add_argument(
            "--target-repo-type",
            choices=["github", "gitlab"],
            help="Target repository [github (default) or gitlab].",
            action=AlphanumericAction,
            max_length=20,
        )
        parser.add_argument(
            "--target-repo-url",
            type=str,
            help="Target repository url (may be optional, depending on repo type etc).",
            action=AlphanumericAction,
            max_length=80,
        )
        parser.add_argument(
            "--working-directory",
            type=str,
            default=os.path.join(unique_temp_path, script_name),
            help="Working directory for temporary git clones etc.",
            action=AlphanumericAction,
            max_length=80,
        )

        # TODO: add backup folder and functionality for svn sync to delete local persistent copy and restore from backup
        # TODO: create optional report output listing actions that need attention, eg. repos that failed to process

        args = parse_arguments(parser=parser)
        if not args:
            raise Exception("Error parsing command line and config file arguments.")

        # Display help if no arguments are provided
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        # Log dry-run mode if enabled
        if args.target_dry_run:
            log_message(LogLevel.INFO, "Dry-run mode enabled. No changes will be made.")

        # Output some useful information as the script starts
        log_message(LogLevel.INFO, "Script name: {}", script_name)
        log_message(LogLevel.INFO, "Version: {}", __version__)

        # Check if running under Jenkins
        if is_running_under_jenkins():
            log_message(LogLevel.INFO, "Running under Jenkins")

        # do any one-off setup based on target_repo_type
        match args.target_repo_type:
            case "github":
                # Get the GitHub access token from an environment variable
                target_access_token = os.getenv("GITHUB_ACCESS_TOKEN")
                if not target_access_token:
                    raise Exception(
                        "GitHub access token not found in environment variable GITHUB_ACCESS_TOKEN."
                    )
                # Authenticate to GitHub
                github_target = authenticate_to_github(
                    access_token=target_access_token,
                    enterprise_url=args.target_repo_url,
                )
                github_user_login = get_github_info(
                    github_target=github_target, indent_level=0
                )
            case "gitlab":
                raise Exception(
                    f"Target repo type {args.target_repo_type} is not yet supported."
                )
            case _:
                raise Exception(
                    f"Invalid Target repository type: {args.target_repo_type}"
                )

        # do any one-off setup based on source_repo_type
        match args.source_repo_type:
            case "subversion":
                if not args.subversion_repo_persistent_storage:
                    raise Exception(
                        "Persistent storage for subversion repos is needed to maintain commit consistency."
                    )
                if not os.path.exists(args.subversion_repo_persistent_storage):
                    raise Exception(
                        f"Subversion persistent storage directory {args.subversion_repo_persistent_storage} does not exist."
                    )
                log_message(
                    LogLevel.INFO,
                    f"Source repo type is subversion, using persistent storage: {args.subversion_repo_persistent_storage}",
                )
            case "gitlab":
                raise Exception(
                    f"Source repo type {args.source_repo_type} is not yet supported."
                )
            case None:
                log_message(
                    LogLevel.INFO, "No source repo type specified, managing target only"
                )
            case _:
                raise Exception(f"Invalid source repository: {args.source_repo_type}")

        # FIXME: we may have to add global git config values for user & email here for any commit's this script does.
        set_global_git_defaults()

        # Create the directory if it does not already exist
        os.makedirs(args.working_directory, exist_ok=True)
        # Change to the directory
        os.chdir(args.working_directory)
        log_message(LogLevel.INFO, "Current working directory: {}", os.getcwd())

        if args.repo_config_file is not None:
            # Change to the directory
            os.chdir(args.working_directory)
            actual_repo_config_file_path = temp_convert_csv_repo_config_file(
                make_full_path(args.config_directory, args.repo_config_file)
            )
            # Read in repository configuration data
            repo_config_data, default_config_data = read_repo_config_data(
                actual_repo_config_file_path, indent_level=1
            )
            if not repo_config_data:
                raise Exception(
                    "No repository configuration data found in file: {} in directory {}",
                    args.repo_config_file,
                    args.config_directory,
                )
            if not default_config_data:
                raise Exception(
                    "No defaults configuration data found in file: {} in directory {}",
                    args.repo_config_file,
                    args.config_directory,
                )
            # Filter repo_config_data based on the --filter-application parameter
            if args.filter_application:
                repo_config_data = {
                    key: value
                    for key, value in repo_config_data.items()
                    if value.get("application", "").lower()
                    == args.filter_application.lower()
                }
            # Filter repo_config_data based on the --filter-repo parameter
            if args.filter_repo:
                repo_config_data = {
                    key: value
                    for key, value in repo_config_data.items()
                    if key.lower() == args.filter_repo.lower()
                }
            # Sort the remaining repo_config_data by repo name
            sorted_repo_config_data = {
                key: repo_config_data[key] for key in sorted(repo_config_data.keys())
            }
            total_repos = len(sorted_repo_config_data)

            # Loop through the sorted repo_config_data
            for index, key in enumerate(sorted_repo_config_data, start=1):
                repo_data = sorted_repo_config_data[key]
                repo_name = key
                repo_owner = repo_data["owner"]

                # Script flow for each target repo is:
                #   STAGE 0: Check API rate limits
                #   STAGE 1: Progress and timing information
                #   STAGE 2: Expected settings for target repository
                #   STAGE 3: Target repository level work
                #            eg create repo, set permissions, set topics
                #   STAGE 4: local directory level work
                #   STAGE 5: Source repo: migrate/update into target repo
                #   STAGE 6: Target repo branch or code level work

                log_message(
                    LogLevel.INFO,
                    f"-------------------------------------------------------------------------",
                    indent_level=0,
                )

                # STAGE 0: Check any API rate limits
                if args.target_repo_type == "github":
                    # check the rate limit on the GitHub API and sleep if needed
                    github_check_rate_limit(github_target=github_target, indent_level=0)
                elif args.target_repo_type == "gitlab":
                    raise Exception(
                        f"Destination repo type {args.target_repo_type} is not yet supported."
                    )
                else:
                    raise Exception(
                        f"Invalid destination repository type: {args.target_repo_type}"
                    )

                # STAGE 1: Time the processing of each repo and estimate the time remaining
                current_time = datetime.now()
                elapsed_time = (current_time - start_time).total_seconds()
                average_time_per_repo = elapsed_time / index
                expected_time_remaining = round(
                    average_time_per_repo * (total_repos - index)
                )
                log_message(
                    LogLevel.INFO,
                    f"-------------------------------------------------------------------------",
                    indent_level=0,
                )
                log_message(
                    LogLevel.INFO,
                    f"Processing target repo {repo_owner}/{repo_name} [repo {index} of {total_repos}, should finish in {expected_time_remaining}s]",
                    indent_level=0,
                )

                # STAGE 2: Expected settings for target repository
                # expected data is a merge of defaults
                # defaults come from the value in [<repo_name>]['repo_settings']['use_defaults'] looked up in ['defaults']['repo_settings'][<name>]
                # this also expands out team_permissions and user_permissions to the full list of teams and users using the defaults
                expected_repo_data = get_expected_repo_data(
                    repo_data, default_config_data, indent_level=1
                )
                if expected_repo_data is None:
                    log_message(
                        LogLevel.ERROR,
                        f"Failed to get expected repo settings for {repo_owner}/{repo_name}",
                        indent_level=1,
                    )
                    continue
                log_message(
                    LogLevel.INFO, f"Got expected repo settings", indent_level=1
                )
                log_message(
                    LogLevel.DEBUG,
                    f"Expected repo settings: {expected_repo_data}",
                    indent_level=1,
                )

                # STAGE 3: Target repository level work
                if args.target_repo_type == "github":
                    # Process the GitHub repo
                    if github_process_target_repo(
                        github_target=github_target,
                        github_user_login=github_user_login,
                        repo_name=repo_name,
                        expected_repo_data=expected_repo_data,
                        indent_level=1,
                        dry_run=args.target_dry_run,
                    ):
                        log_message(
                            LogLevel.INFO,
                            f"Successfully processed {repo_owner}/{repo_name}",
                            indent_level=1,
                        )
                    else:
                        log_message(
                            LogLevel.ERROR,
                            f"Failed to process {repo_owner}/{repo_name}",
                            indent_level=1,
                        )
                    target_repo_url = get_github_repo_url(
                        github_target=github_target,
                        repo_name=repo_name,
                        repo_owner=repo_owner,
                        indent_level=1,
                    )
                elif args.target_repo_type == "gitlab":
                    target_repo_url = None
                    raise Exception(
                        f"Destination repo type {args.target_repo_type} is not yet supported."
                    )
                else:
                    raise Exception(
                        f"Invalid destination repository type: {args.target_repo_type}"
                    )

                # STAGE 4: local directory level work
                # Create the directory if it does not already exist
                repo_working_directory = os.path.join(args.working_directory, repo_name)
                os.makedirs(repo_working_directory, exist_ok=True)
                # Change to the directory
                os.chdir(repo_working_directory)
                log_message(
                    LogLevel.INFO,
                    "Current working directory: {}",
                    os.getcwd(),
                    indent_level=1,
                )

                # STAGE 5: Source repo: migrate/update into target repo
                log_message(LogLevel.INFO, "Processing source repo", indent_level=1)
                if args.source_repo_type == "subversion":
                    log_message(
                        LogLevel.INFO,
                        "Syncing from Subversion source repo",
                        indent_level=1,
                    )
                    # Change to the persistent storage directory
                    try:
                        os.chdir(args.subversion_repo_persistent_storage)
                    except OSError:
                        log_message(
                            LogLevel.ERROR,
                            f"Failed to change to persistent storage directory {args.subversion_repo_persistent_storage}",
                            indent_level=1,
                        )
                        continue
                    os.makedirs(repo_name, exist_ok=True)
                    try:
                        os.chdir(repo_name)
                    except OSError:
                        log_message(
                            LogLevel.ERROR,
                            f"Failed to change to persistent storage directory {args.subversion_repo_persistent_storage}/{repo_name}",
                            indent_level=1,
                        )
                        continue
                    log_message(
                        LogLevel.INFO,
                        "Current working directory: {}",
                        os.getcwd(),
                        indent_level=2,
                    )
                    # Process the SVN source repo
                    if process_svn_source_repo(
                        expected_repo_data=expected_repo_data,
                        target_repo_url=target_repo_url,
                        args=args,
                        indent_level=1,
                    ):
                        log_message(
                            LogLevel.INFO,
                            "Successfully processed source repo",
                            indent_level=1,
                        )
                    else:
                        log_message(
                            LogLevel.ERROR,
                            f"Failed to process source repo {repo_owner}/{repo_name}",
                            indent_level=1,
                        )
                        continue
                elif args.source_repo_type == "gitlab":
                    raise Exception(
                        f"Source repo type {args.source_repo_type} is not yet supported."
                    )
                elif args.source_repo_type == "github":
                    raise Exception(
                        f"Source repo type {args.source_repo_type} is not yet supported."
                    )
                else:
                    log_message(
                        LogLevel.INFO,
                        "No source repo processing required",
                        indent_level=1,
                    )

                # STAGE 7: Target repo - branch or code level work

                # end of the loop around target repos

            # Output the completion and total run time of the script
            current_time = datetime.now()
            elapsed_time = (current_time - start_time).total_seconds()
            average_time_per_repo = elapsed_time / total_repos if total_repos > 0 else 0
            log_message(
                LogLevel.INFO,
                f"Total run time: {round(elapsed_time)} seconds. Processed {total_repos} repos, avg time per repo {round(average_time_per_repo)}s",
                indent_level=0,
            )

        else:
            # no repo config file specified
            log_message(LogLevel.INFO, "No repo config file specified", indent_level=0)

        # Check for unmanaged repos in the destination.
        if args.target_repo_type == "github":
            if args.github_org_to_scan and args.repo_config_file is not None:
                log_message(
                    LogLevel.INFO,
                    f"Scanning GitHub organization {args.github_org_to_scan} for unmanaged repositories",
                    indent_level=0,
                )
                # Get a list of all repositories in the organization
                org_repos = github_target.get_organization(
                    args.github_org_to_scan
                ).get_repos()
                for repo in org_repos:
                    if not repo.archived:
                        if repo.name not in repo_config_data:
                            log_message(
                                LogLevel.ERROR,
                                f"Unmanaged repository: {repo.full_name}",
                                indent_level=1,
                            )
        elif args.target_repo_type == "gitlab":
            if args.gitlab_org_to_scan and args.repo_config_file is not None:
                log_message(
                    LogLevel.ERROR,
                    f"Destination repo type {args.target_repo_type} is not yet supported for scanning.",
                    indent_level=0,
                )

        log_message(LogLevel.INFO, "Script completed.")

    except Exception as e:
        try:
            log_message(LogLevel.CRITICAL, "An unexpected error occurred: {}", e)
            if args and args.log_level:
                log_level_setting = args.log_level.lower()
            else:
                log_level_setting = "info"
            if log_level_setting == "debug":
                traceback.print_exc(limit=5)

            sys.exit(1)  # return a non-zero error code
        except SystemExit:
            pass  # don't log a critical error if we are already exiting


if __name__ == "__main__":
    main()
