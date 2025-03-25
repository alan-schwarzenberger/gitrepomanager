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
from setuptools import setup, find_packages

# Read the version from the version.py file
version = {}
with open(os.path.join("gitrepomanager", "version.py")) as fp:
    exec(fp.read(), version)

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt") as f:
    install_requires = [
        line.strip() for line in f if line.strip() and not line.startswith("#")
    ]

setup(
    name="gitrepomanager",
    version=version["__version__"],
    author="EPAM Systems",
    description="Git repository manager",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/epam/gitrepomanager",
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "gitrepomanager=gitrepomanager.git_repo_manager:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Version Control :: Git",
    ],
    python_requires=">=3.6",
)
