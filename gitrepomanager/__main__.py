import sys
from pathlib import Path

# Add the parent directory to the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gitrepomanager.git_repo_manager import main

if __name__ == "__main__":
    main()
