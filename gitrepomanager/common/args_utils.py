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
import re
from gitrepomanager.common.logging_utils import configure_logging
from gitrepomanager.common.logging_utils import log_message
from gitrepomanager.common.logging_utils import LogLevel
from gitrepomanager.common.repo_config_file_ops import csv_file_to_json_file
from gitrepomanager.common.repo_config_file_ops import load_config_from_file
from gitrepomanager.common.repo_config_file_ops import make_full_path
from gitrepomanager.common.repo_config_file_ops import temp_convert_csv_repo_config_file


class AlphanumericAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        self.max_length = kwargs.pop("max_length", None)
        super().__init__(option_strings, dest, nargs=nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if not re.match(r"^[a-zA-Z0-9\-\.\\/_]+$", values):
            parser.error(
                f"Argument {self.dest} contains invalid characters. Only alphanumeric characters, '-', '_', '' and '/' are allowed."
            )
        if self.max_length and len(values) > self.max_length:
            parser.error(
                f"Argument {self.dest} exceeds maximum length of {self.max_length} characters."
            )
        vars(namespace)[self.dest] = values


def parse_arguments(*, parser, indent_level=0):
    # args are read in this order. EARLIER ones overwrite LATER ones:
    # command line > script_config_file > repo_config_file['settings']
    if not isinstance(parser, argparse.ArgumentParser):
        raise TypeError("parser must be an instance of argparse.ArgumentParser")
    try:
        args = parser.parse_args()

        # Load configuration from script_config_file
        if args.script_config_file:
            script_config_file_path = make_full_path(
                args.config_directory, args.script_config_file
            )
            config = load_config_from_file(script_config_file_path)
            # Update the args namespace with the config values
            if config is not None:
                for key, value in config.items():
                    # only update the args namespace if the key exists in args
                    # anything not set on command line will already be in args namespace as None
                    # this ensures that only the keys that are valid for the script are updated,
                    # and that command line arguments take precedence
                    if key in vars(args):
                        if vars(args)[key] is None:
                            vars(args)[key] = value
                    else:
                        log_message(
                            LogLevel.INFO,
                            "Script config file contained invalid key: {}",
                            key,
                        )  # can only use info level here
            else:
                log_message(
                    LogLevel.INFO,
                    "Script config file specified but contained no config: {}",
                    args.script_config_file,
                )  # can only use info level here

            # Check if log_level is set and valid
            if args.log_level:
                if not args.log_level.upper() in LogLevel.__members__:
                    raise ValueError(
                        f"Invalid log level from script config file: {args.log_level}"
                    )
                configure_logging(log_level=LogLevel[args.log_level.upper()])

        # Load script configuration from repo_config_file if 'settings' key is present
        if args.repo_config_file:
            repo_config_file_path = make_full_path(
                args.config_directory, args.repo_config_file
            )
            log_message(
                LogLevel.DEBUG, "Repo config file: {}", repo_config_file_path
            )  # will only show if log level debug was set by now
            actual_repo_config_file_path = temp_convert_csv_repo_config_file(
                repo_config_file_path, indent_level=indent_level
            )
            log_message(
                LogLevel.DEBUG,
                "Actual repo config file: {}",
                actual_repo_config_file_path,
            )  # will only show if log level debug was set by now
            config_data = load_config_from_file(actual_repo_config_file_path)
            if config_data is not None and "settings" in config_data:
                for key, value in config_data["settings"].items():
                    # only update the args namespace if the key exists in args
                    # anything not set on command line will already be in args namespace as None
                    # this ensures that only the keys that are valid for the script are updated
                    # and that command line arguments and script config file values take precedence
                    if key in vars(args):
                        if vars(args)[key] is None:
                            vars(args)[key] = value
                    else:
                        log_message(
                            LogLevel.INFO,
                            "Repo config file contained invalid settings key: {}",
                            key,
                        )
            else:
                log_message(
                    LogLevel.DEBUG,
                    "Checked repo_config file, but script config not found inside: {}",
                    actual_repo_config_file_path,
                )

            # Check if log_level is set and valid
            if args.log_level:
                if not args.log_level.upper() in LogLevel.__members__:
                    raise ValueError(
                        f"Invalid log level from repo config file: {args.log_level}"
                    )
                configure_logging(log_level=LogLevel[args.log_level.upper()])

        log_message(LogLevel.DEBUG, "Arguments (net): {}", args)
        return args

    except Exception as e:
        log_message(
            LogLevel.CRITICAL,
            "Error parsing arguments or loading config file: {}",
            format(e),
        )
        return None
