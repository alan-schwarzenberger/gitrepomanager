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

import git
import os
from gitrepomanager.common.cmd_utils import create_unique_temp_directory
from gitrepomanager.common.cmd_utils import delete_directory
from gitrepomanager.common.logging_utils import log_message
from gitrepomanager.common.logging_utils import LogLevel


def git_add_remote_and_push(
    *, repo_path, remote_url, remote_name, branch_name, indent_level=0
):
    try:
        if not is_git_repo(repo_path):
            log_message(
                LogLevel.ERROR,
                "The directory is not a Git repository.",
                indent_level=indent_level,
            )
            return False
        repo = git.Repo(repo_path)
        if remote_name not in [remote.name for remote in repo.remotes]:
            repo.create_remote(remote_name, remote_url)
            log_message(
                LogLevel.INFO,
                f"Remote '{remote_name}' added with URL {remote_url}.",
                indent_level=indent_level,
            )
        else:
            log_message(
                LogLevel.DEBUG,
                f"Remote '{remote_name}' already exists.",
                indent_level=indent_level,
            )
        if branch_name not in repo.heads:
            log_message(
                LogLevel.INFO,
                f"Branch '{branch_name}' does not exist in the repository.",
                indent_level=indent_level,
            )
            return False

        return git_push(
            repo_path=repo_path,
            remote_name=remote_name,
            branch_name=branch_name,
            indent_level=indent_level,
        )

    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"An error occurred while adding remote and pushing {remote_name}: {e}",
            indent_level=indent_level + 1,
        )
        return False


def git_push(*, repo_path, remote_name, branch_name, indent_level):
    try:
        repo = git.Repo(repo_path)
        output = repo.git.push(remote_name, branch_name)
        log_message(LogLevel.INFO, f"Push output: {output}", indent_level=indent_level)
        return True
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"An error occurred while pushing {branch_name}",
            indent_level=indent_level,
        )
        log_message(LogLevel.DEBUG, f"{e}", indent_level=indent_level + 1)
        return False


def git_remote_defined(*, repo_path, remote_name="origin", indent_level=0):
    try:
        repo = git.Repo(repo_path)
        if remote_name not in [remote.name for remote in repo.remotes]:
            return False
        else:
            return True
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"An error occurred while checking remote '{remote_name}': {e}",
            indent_level=indent_level + 1,
        )
        return False


def git_add_remote(*, repo_path, remote_url, remote_name="origin", indent_level=0):
    try:
        if not is_git_repo(repo_path):
            log_message(
                LogLevel.ERROR,
                "The directory is not a Git repository.",
                indent_level=indent_level,
            )
            return False
        if git_remote_defined(
            repo_path=repo_path, remote_name=remote_name, indent_level=indent_level
        ):
            log_message(
                LogLevel.INFO,
                f"Remote '{remote_name}' already exists.",
                indent_level=indent_level,
            )
            return True
        else:
            repo = git.Repo(repo_path)
            repo.create_remote(remote_name, remote_url)
            log_message(
                LogLevel.INFO,
                f"Remote '{remote_name}' added with URL {remote_url}.",
                indent_level=indent_level,
            )
            return True
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"An error occurred while adding remote {remote_name}: {e}",
            indent_level=indent_level + 1,
        )
        return False


def git_get_branch_ahead_behind(
    *, repo_path, branch_name="main", remote_name="origin", indent_level=0
):
    try:
        repo = git.Repo(repo_path)
        remote_branch = f"{remote_name}/{branch_name}"
        # Get the commits that are in branch but not in remote_branch
        ahead_commits = list(repo.iter_commits(f"{remote_branch}..{branch_name}"))
        # Get the commits that are in remote_branch but not in branch
        behind_commits = list(repo.iter_commits(f"{branch_name}..{remote_branch}"))

        ahead_count = len(ahead_commits)
        behind_count = len(behind_commits)

        log_message(
            LogLevel.INFO,
            f"Branch '{branch_name}' is {ahead_count} commits ahead and {behind_count} commits behind its remote '{remote_name}/{branch_name}'.",
            indent_level=indent_level,
        )
        return ahead_count, behind_count
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"An error occurred while checking ahead/behind status: {e}",
            indent_level=indent_level + 1,
        )
        raise


def git_branch_exists(*, repo_path=os.path, branch_name, indent_level=0):
    # acts locally only
    try:
        repo = git.Repo(repo_path)
        if branch_name in repo.branches:
            log_message(
                LogLevel.INFO,
                "Branch '{}' exists in the repository.",
                branch_name,
                indent_level=indent_level,
            )
            return True
        else:
            log_message(
                LogLevel.INFO,
                "Branch '{}' does not exist in the repository.",
                branch_name,
                indent_level=indent_level,
            )
            return False
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            "Failed to check if branch '{}' exists: {}",
            branch_name,
            e,
            indent_level=indent_level,
        )
        return False


def git_checkout_branch(*, repo_path=os.path, branch_name, indent_level=0):
    # acts locally only
    try:
        repo = git.Repo(repo_path)
        repo.git.checkout(branch_name)
        log_message(
            LogLevel.INFO,
            "Checked out branch '{}'.",
            branch_name,
            indent_level=indent_level,
        )
        return True
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            "Failed to checkout branch '{}': {}",
            branch_name,
            e,
            indent_level=indent_level,
        )
        return False


def git_create_empty_main_branch(*, repo_path, indent_level=0):
    try:
        repo = git.Repo(repo_path)
        # create a new orphaned branch
        output = repo.git.checkout("--orphan", "main")
        log_message(
            LogLevel.DEBUG,
            f"Output from checkout orphan main: {output}",
            indent_level=indent_level,
        )
        # remove all staged files
        output = repo.git.rm("-rf", ".")
        log_message(
            LogLevel.DEBUG,
            f"Output from removing staged files: {output}",
            indent_level=indent_level,
        )
        # clean the working directory
        output = repo.git.clean("-fdx")
        log_message(
            LogLevel.DEBUG,
            f"Output from cleaning working directory: {output}",
            indent_level=indent_level,
        )
        # Create a new empty commit
        output = repo.index.commit(f"Initial empty commit")
        log_message(
            LogLevel.DEBUG,
            f"Output from empty commit: {output}",
            indent_level=indent_level,
        )
        log_message(
            LogLevel.INFO,
            "Empty main branch created successfully.",
            indent_level=indent_level,
        )
        return True
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"An error occurred while creating the empty main branch: {e}",
            indent_level=indent_level + 1,
        )
        return False


def git_rename_local_branch(
    *, repo_path, old_branch_name, new_branch_name, indent_level=0
):
    try:
        repo = git.Repo(repo_path)
        if old_branch_name not in repo.branches:
            log_message(
                LogLevel.ERROR,
                "Branch '{}' does not exist in the repository.",
                old_branch_name,
                indent_level=indent_level,
            )
            return False
        output = repo.git.branch("-m", old_branch_name, new_branch_name)
        log_message(
            LogLevel.DEBUG,
            f"Output from branch rename: {output}",
            indent_level=indent_level,
        )
        log_message(
            LogLevel.INFO,
            "Renamed branch '{}' to '{}'.",
            old_branch_name,
            new_branch_name,
            indent_level=indent_level,
        )
        return True
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            "Failed to rename branch '{}' to '{}': {}",
            old_branch_name,
            new_branch_name,
            e,
            indent_level=indent_level,
        )
        return False


def is_git_repo(directory):
    """
    Check if the given directory is a git repository.

    :param directory: Path to the directory to check.
    :return: True if the directory is a git repository, False otherwise.
    """
    try:
        _ = git.Repo(directory).git_dir
        return True
    except git.exc.InvalidGitRepositoryError:
        return False
    except Exception as e:
        return False


def is_main_the_only_branch(repo_path, indent_level=0):
    try:
        repo = git.Repo(repo_path)
        branches = repo.branches
        if len(branches) == 1 and branches[0].name == "main":
            log_message(
                LogLevel.INFO,
                "Main is the only branch in the repository.",
                indent_level=indent_level,
            )
            return True
        else:
            log_message(
                LogLevel.DEBUG,
                f"Branches in the repository: {[branch.name for branch in branches]}",
            )
            return False
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"An error occurred while checking branches: {e}",
            indent_level=indent_level,
        )
        return False


def set_global_git_defaults():
    try:
        unique_temp_dir = create_unique_temp_directory()
        # Initialize a temporary repository to set global config
        repo = git.Repo.init(unique_temp_dir)
        repo.git.config("--global", "init.defaultBranch", "main")
        log_message(LogLevel.INFO, "Global default Git branch set to 'main'")
    except Exception as e:
        log_message(LogLevel.ERROR, "Failed to set Git global defaults: {}", e)
    finally:
        delete_directory(unique_temp_dir)


def convert_subversion_tag_branches_to_git_tags(repo_path, indent_level=0):
    try:
        repo = git.Repo(repo_path)
        log_message(
            LogLevel.INFO,
            "Converting any subversion tag branches to Git tags",
            indent_level=indent_level,
        )

        # Deleting local branches that match 'tags/*'
        for branch in repo.branches:
            if branch.name.startswith("tags/"):
                log_message(
                    LogLevel.INFO,
                    f"Deleting local branch {branch.name}",
                    indent_level=indent_level + 1,
                )
                try:
                    repo.delete_head(branch, force=True)
                except git.exc.GitCommandError as e:
                    log_message(
                        LogLevel.ERROR,
                        f"Failed to delete branch {branch.name}: {e}",
                        indent_level=indent_level + 2,
                    )

        # Converting remote branches that match 'remotes/svn/tags/*' to tags
        for remote_branch in repo.remote().refs:
            if remote_branch.name.startswith("refs/remotes/svn/tags/"):
                tag_name = remote_branch.name.replace("refs/remotes/svn/tags/", "")
                log_message(
                    LogLevel.INFO,
                    f"Converting tag {tag_name}",
                    indent_level=indent_level + 1,
                )
                try:
                    repo.create_tag(tag_name, ref=remote_branch)
                    repo.delete_remote_branch(remote_branch)
                except git.exc.GitCommandError as e:
                    log_message(
                        LogLevel.ERROR,
                        f"Failed to convert tag {tag_name}: {e}",
                        indent_level=indent_level + 2,
                    )
    except Exception as e:
        log_message(
            LogLevel.ERROR,
            f"An error occurred during tag conversion: {e}",
            indent_level=indent_level,
        )
