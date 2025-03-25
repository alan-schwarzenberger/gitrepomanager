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

import logging
import re
from datetime import datetime
from enum import Enum

# Define the logger as a global variable so we don;t have to pass these on every function call
logger = None
file_handler = None
console_handler = None


# Define the LogLevel Enum
class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


def configure_logging(
    *, start_time=None, log_to_file=False, log_to_console=True, log_level=LogLevel.INFO
):
    global logger
    global file_handler
    global console_handler

    if logger is None:
        logger = logging.getLogger(__name__)
        logger.setLevel(log_level.value.upper())

        time_format = "%Y-%m-%d %H:%M:%S"
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(levelname)-8s %(message)s", datefmt=time_format
        )

        if log_to_file:
            if start_time is None:
                raise ValueError(
                    "Script internal error: start_time parameter is required when log_to_file is True"
                )
            log_file_path = f"app_{start_time.strftime('%Y%m%d_%H%M%S')}.log"
            file_handler = logging.FileHandler(log_file_path, mode="w")
            file_handler.setLevel(log_level.value.upper())
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        if log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level.value.upper())
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        if log_to_file is False and log_to_console is False:
            # in theory you could have neither, but that would be a bit silly so we won't allow it
            raise ValueError(
                "At least one of log_to_file or log_to_console must be True"
            )

    else:
        # Update the log level if the logger is already configured
        logger.setLevel(log_level.value.upper())
        # Also update the log level for the handlers
        if console_handler is not None:
            console_handler.setLevel(log_level.value.upper())
        if file_handler is not None:
            file_handler.setLevel(log_level.value.upper())

    return logger


# Function to log messages
def log_message(level, message, *args, indent_level=0, filter_lines=None):
    global logger
    if logger is None:
        raise ValueError(
            "Script internal error: logger is not configured. Please ensure you call configure_logging() first."
        )

    if not isinstance(level, LogLevel):
        raise ValueError(
            f"Internal error, invalid log level: {level}. Must be an instance of LogLevel Enum."
        )

    if filter_lines and re.match(filter_lines, message.strip()):
        return

    indent = " " * (indent_level * 4)
    formatted_message = message.format(*args) if args else message
    lines = formatted_message.splitlines()
    for line in lines:
        if filter_lines and re.match(filter_lines, line.strip()):
            continue

        formatted_line = indent + line
        logs = {
            LogLevel.DEBUG: logger.debug,
            LogLevel.INFO: logger.info,
            LogLevel.WARNING: logger.warning,
            LogLevel.ERROR: logger.error,
            LogLevel.CRITICAL: logger.critical,
        }

        if function := logs.get(level):
            function(formatted_line)
        else:
            raise ValueError(f"Invalid log level: {level}")
