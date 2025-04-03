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
import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the git executable is in the PATH
os.environ["GIT_PYTHON_REFRESH"] = "quiet"

# Add the parent directory to the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gitrepomanager.git_repo_manager import is_running_under_jenkins, main


def test_is_running_under_jenkins():
    # Test when JENKINS_HOME is not in the environment
    if "JENKINS_HOME" in os.environ:
        del os.environ["JENKINS_HOME"]
    assert not is_running_under_jenkins()

    # Test when JENKINS_HOME is in the environment
    os.environ["JENKINS_HOME"] = "/some/path"
    assert is_running_under_jenkins()
    del os.environ["JENKINS_HOME"]


def test_target_dry_run():
    # Mock the GitHub API client
    with patch("gitrepomanager.common.github_utils.Github") as MockGithub:
        mock_github_instance = MockGithub.return_value
        mock_repo = MagicMock()
        mock_github_instance.get_repo.return_value = mock_repo

        # Mock repository methods
        mock_repo.get_contents.side_effect = Exception(
            "This should not be called in dry-run mode"
        )
        mock_repo.create_file.side_effect = Exception(
            "This should not be called in dry-run mode"
        )
        mock_repo.update_file.side_effect = Exception(
            "This should not be called in dry-run mode"
        )

        # Prepare arguments for the script
        args = [
            "--script-config-file",
            "../sample_config/sample-script-config.json",
            "--log-level",
            "INFO",
            "--target-dry-run",
        ]

        # Run the script
        with patch("sys.argv", ["gitrepomanager"] + args):
            main()

        # Assert that no changes were made
        mock_repo.create_file.assert_not_called()
        mock_repo.update_file.assert_not_called()
