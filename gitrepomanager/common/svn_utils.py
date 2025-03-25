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

import os
from gitrepomanager.common.cmd_utils import delete_big_files_from_dir
from gitrepomanager.common.cmd_utils import run_command_log_output
from gitrepomanager.common.git_utils import convert_subversion_tag_branches_to_git_tags
from gitrepomanager.common.git_utils import git_add_remote
from gitrepomanager.common.git_utils import git_add_remote_and_push
from gitrepomanager.common.git_utils import git_branch_exists
from gitrepomanager.common.git_utils import git_checkout_branch
from gitrepomanager.common.git_utils import git_create_empty_main_branch
from gitrepomanager.common.git_utils import git_get_branch_ahead_behind
from gitrepomanager.common.git_utils import git_push
from gitrepomanager.common.git_utils import git_remote_defined
from gitrepomanager.common.git_utils import git_rename_local_branch
from gitrepomanager.common.git_utils import is_git_repo
from gitrepomanager.common.logging_utils import log_message
from gitrepomanager.common.logging_utils import LogLevel


def process_svn_source_repo(
    *, expected_repo_data, args, target_repo_url, indent_level=0
):

    # note that to keep modular we can use git commands here, but not github (or other target repo) commands.
    # Current working directory is the local Git repository
    try:
        svnrepo = expected_repo_data.get("source_repo", None)
        if not svnrepo:
            log_message(
                LogLevel.ERROR,
                "No source repository provided.",
                indent_level=indent_level + 1,
            )
            return False

        svnrevisionflag = (
            ""
            if not expected_repo_data.get("subversion_revision")
            else f"--revision=0:{expected_repo_data.get('subversion_revision')}"
        )

        if expected_repo_data.get("sync_from_source", False):
            first_run = False
            ignore_paths = (
                f"--ignore-paths='{expected_repo_data['subversion_ignore_paths']}'"
                if expected_repo_data.get("subversion_ignore_paths")
                else ""
            )
            # Check if the Git repository exists
            if not is_git_repo(os.getcwd()):
                # TODO: add option to restore from backup here
                log_message(
                    LogLevel.INFO,
                    "The local Git repository does not exist.",
                    indent_level=indent_level + 1,
                )
                try:
                    run_command_log_output(
                        f"git svn init {svnrepo} {ignore_paths}",
                        indent_level=indent_level + 2,
                    )
                    log_message(
                        LogLevel.INFO,
                        "Fetching SVN repository.",
                        indent_level=indent_level + 1,
                    )
                    run_command_log_output(
                        f"git svn fetch {svnrevisionflag} {ignore_paths}",
                        filter_lines=r"^[ADMW]\s|^Updating files:\s",
                        indent_level=indent_level + 2,
                    )
                    log_message(
                        LogLevel.INFO,
                        "Fetched SVN repository.",
                        indent_level=indent_level + 1,
                    )
                    log_message(
                        LogLevel.INFO,
                        "Checking for large files.",
                        indent_level=indent_level + 1,
                    )
                    delete_big_files_from_dir(
                        dir=os.getcwd(),
                        maxsize=48,
                        recursive=True,
                        indent_level=indent_level + 2,
                    )
                    first_run = True
                except Exception as e:
                    log_message(
                        LogLevel.ERROR,
                        f"An error occurred first time fetching from svn: {e}",
                        indent_level=indent_level + 1,
                    )
                    return False
            else:
                log_message(
                    LogLevel.INFO,
                    "The local Git repository already exists.",
                    indent_level=indent_level + 1,
                )

            # check we have a remote origin (on the repo not the branch)
            if not git_remote_defined(repo_path=os.getcwd(), remote_name="origin"):
                git_add_remote(
                    repo_path=os.getcwd(),
                    remote_url=target_repo_url,
                    remote_name="origin",
                    indent_level=indent_level + 1,
                )

            # if we only have a main branch, then we need to rename it to main-svn
            log_message(
                LogLevel.INFO,
                "Checking branches in local repo.",
                indent_level=indent_level + 1,
            )
            if git_branch_exists(
                repo_path=os.getcwd(), branch_name="main", indent_level=indent_level + 2
            ) and not git_branch_exists(
                repo_path=os.getcwd(),
                branch_name="main-svn",
                indent_level=indent_level + 2,
            ):
                git_rename_local_branch(
                    repo_path=os.getcwd(),
                    old_branch_name="main",
                    new_branch_name="main-svn",
                    indent_level=indent_level + 2,
                )
                if not git_create_empty_main_branch(
                    repo_path=os.getcwd(), indent_level=indent_level + 2
                ):
                    log_message(
                        LogLevel.ERROR,
                        "Push of main branch failed, seems branches have diverged, which is unexpected here.",
                        indent_level=indent_level + 1,
                    )
                    log_message(
                        LogLevel.ERROR,
                        "Either local repo needs deleting and restoring from backup, or both local & remote repos need deleting",
                        indent_level=indent_level + 1,
                    )
                    return False
                git_checkout_branch(
                    repo_path=os.getcwd(),
                    branch_name="main",
                    indent_level=indent_level + 2,
                )
                # make sure we push 'main' first so it becomes the default branch on the remote, at least that works for GitHub and avoids any GitHub functions being called here!
                git_add_remote_and_push(
                    repo_path=os.getcwd(),
                    remote_url=target_repo_url,
                    branch_name="main",
                    remote_name="origin",
                    indent_level=indent_level + 2,
                )
                git_checkout_branch(
                    repo_path=os.getcwd(),
                    branch_name="main-svn",
                    indent_level=indent_level + 2,
                )
                if not git_add_remote_and_push(
                    repo_path=os.getcwd(),
                    remote_url=target_repo_url,
                    branch_name="main-svn",
                    remote_name="origin",
                    indent_level=indent_level + 2,
                ):
                    log_message(
                        LogLevel.ERROR,
                        "Push of main-svn branch failed, likely remote repo contains unexpected commits.",
                        indent_level=indent_level + 1,
                    )
                    log_message(
                        LogLevel.ERROR,
                        "Either local repo needs deleting and restoring from backup, or both local & remote repos need deleting",
                        indent_level=indent_level + 1,
                    )
                    return False

            # check how many commits ahead/behind we are
            ahead, behind = git_get_branch_ahead_behind(
                repo_path=os.getcwd(),
                branch_name="main-svn",
                remote_name="origin",
                indent_level=indent_level + 1,
            )
            if ahead:
                log_message(
                    LogLevel.INFO,
                    f"The main-svn branch is {ahead} commits ahead of the remote origin.",
                    indent_level=indent_level + 1,
                )
            if behind:
                log_message(
                    LogLevel.ERROR,
                    f"The main-svn branch is {behind} commits behind the remote origin.",
                    indent_level=indent_level + 1,
                )
                return False

            # git checkout main-svn (branch we sync from)
            if git_branch_exists(
                repo_path=os.getcwd(),
                branch_name="main-svn",
                indent_level=indent_level + 1,
            ):
                try:
                    git_checkout_branch(
                        repo_path=os.getcwd(),
                        branch_name="main-svn",
                        indent_level=indent_level + 1,
                    )
                except Exception as e:
                    log_message(
                        LogLevel.ERROR,
                        f"An error occurred while checking out the main-svn branch: {e}",
                        indent_level=indent_level + 1,
                    )
                    return False
            else:
                log_message(
                    LogLevel.ERROR,
                    "The main-svn branch does not exist in the repository.",
                    indent_level=indent_level + 1,
                )
                return False

            if not first_run:
                # if this was the first run, we just did a fetch above, so don't need to do this again
                try:
                    log_message(
                        LogLevel.INFO,
                        "Rebasing from SVN repository.",
                        indent_level=indent_level + 1,
                    )
                    run_command_log_output(
                        f"git svn rebase {svnrevisionflag} {ignore_paths}",
                        filter_lines=r"^[ADMW]\s",
                        indent_level=indent_level + 1,
                    )
                    log_message(
                        LogLevel.INFO,
                        "Rebased from SVN repository.",
                        indent_level=indent_level + 1,
                    )
                    log_message(
                        LogLevel.INFO,
                        "Checking for large files.",
                        indent_level=indent_level + 1,
                    )
                    delete_big_files_from_dir(
                        dir=os.getcwd(),
                        maxsize=48,
                        recursive=True,
                        indent_level=indent_level + 2,
                    )
                except Exception as e:
                    log_message(
                        LogLevel.ERROR,
                        f"An error occurred rebasing from svn: {e}",
                        indent_level=indent_level + 1,
                    )
                    return False

            convert_subversion_tag_branches_to_git_tags(
                repo_path=os.getcwd(), indent_level=indent_level + 1
            )

            # push changes to remote
            git_push(
                repo_path=os.getcwd(),
                branch_name="main-svn",
                remote_name="origin",
                indent_level=indent_level + 1,
            )

        else:
            log_message(
                LogLevel.INFO,
                "No source repository actions defined.",
                indent_level=indent_level + 1,
            )
            return False

        return True

    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"An error occurred while processing the source repository: {e}",
            indent_level=indent_level + 1,
        )
        return False
