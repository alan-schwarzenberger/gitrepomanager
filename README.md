# GitRepoManager

GitRepoManager is a Python program designed to help you manage git repositories as code and at scale. This is designed to be run regularly to enforce desired configuration of git repos and report on un-managed repos.
A highly flexible JSON configuration file syntax minimises the per-repo configuration needed, and allows multiple different baseline configurations to be defined,
Additional functionality may be used to migrate repositories between different repository types (Subversion, Gitlab, GitHub etc) including (for some combinations) incremental migration.

## Current repositoy types supported

1. Batch Migration: Migrate multiple repositories at once.
2. Customizable: Configure destination organization, access permissions, and other settings.
3. Error Handling: Gracefully handles common errors and provides meaningful messages.
4. Authentication: Supports GitHub OAuth tokens for secure access.
5. Logging: Provides detailed logs for audit and error tracking.

## Prerequisites

- Python 3.12+ (because of the use of a match statement, so could easily be changed to 3.6+)
- For dependencies see requirements.txt

## Installation

```bash
pip install gitrepomanager
```

## Usage examples

### Management of GitHub repositories as code

1. Generate a GitHub Access Token that has scopes ```repo``` and ```admin:org```
2. Configure Migration Settings (see detailed section on configuration files)
3. Run the Migration:

Execute the Python script to start the migration process.

```bash
python gitrepomanager --script-config-file path/to/script-config-file.json --repo-config-file path/to/repo-config-file.json
```

4. Monitor the Log output on console or file (depending on options chosen)
ach migration.

## Configuration

You can specify two JSON configuration files for your migration or setup:

1. **script-config-file**  
   This file should be used to set global options such as logging, environment settings, and default behaviors. Example:
   ```json
   {
     "logLevel": "INFO",
     "outputDirectory": "/path/to/logs",
     "dryRun": false
   }

2. **repo-config-file**
   This file should be used to 


## Contributing

Full details available on [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (c) 2025 EPAM Systems

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Acknowledgments

GitHub Developer Documentation

Open-source code used in our code:
- none

Open-source libraries and tools used to build or run this project are listed in [requirements.txt](requirements.txt) and include:
- PyGithub https://github.com/PyGithub/PyGithub (GPL or GPL lesser license)
- GitPython https://github.com/gitpython-developers/GitPython (BSD 3-clause revised license)
- Black https://github.com/psf/black (MIT license)
- Setuptools https://github.com/pypa/setuptools (MIT license)

