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
import shutil
import subprocess
import tempfile
from gitrepomanager.common.logging_utils import log_message
from gitrepomanager.common.logging_utils import LogLevel


def run_command_log_output(
    command, working_dir=None, filter_lines=None, indent_level=0
):
    try:
        # Run the git svn command
        process = subprocess.Popen(
            command if isinstance(command, list) else command.split(),
            bufsize=1,  # Output is line buffered, required to print output in real time
            cwd=working_dir,  # If working_dir is None, the current working directory is used
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            text=True,
            universal_newlines=True,  # Required for line buffering
        )

        # Stream the output line by line
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                log_message(
                    LogLevel.INFO,
                    output.strip(),
                    filter_lines=filter_lines,
                    indent_level=indent_level,
                )

        # Wait for the process to complete
        process.wait()

        return process.returncode
    except subprocess.CalledProcessError as e:
        raise Exception(f"An error occurred while running the command {command}: {e}")


def create_unique_temp_directory():
    try:
        temp_dir = tempfile.mkdtemp()
        return temp_dir
    except Exception as e:
        raise


def delete_directory(dir):
    try:
        shutil.rmtree(dir)
    except Exception as e:
        raise


def delete_big_files_from_dir(*, dir, recursive=False, maxsize=48, indent_level=0):
    try:
        for root, dirs, files in os.walk(dir):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.getsize(file_path) > maxsize * 1024 * 1024:
                    os.remove(file_path)
                    log_message(
                        LogLevel.INFO,
                        f"Deleted file {file_path} as it was larger than {maxsize}MB.",
                        indent_level=indent_level,
                    )
            if not recursive:
                break
    except Exception as e:
        raise
