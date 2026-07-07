import os

# --- Configuration ---
OUTPUT_FILE = "codebase_dump.txt"
ROOT_DIR = "."

# Directories to skip completely
EXCLUDE_DIRS = {
    'node_modules',
    'coverage',
    'build',
    '.git',
    '__pycache__',
    'dist',
    '.next'
}

# FIX: Dynamically exclude THIS script by resolving its own filename
# Previously hardcoded as 'dump_code.py' while the script is named 'some.py'
_THIS_FILE = os.path.basename(__file__)

EXCLUDE_FILES = {
    _THIS_FILE,           # FIX: always excludes itself regardless of script name
    '.DS_Store',
    'package-lock.json',
    'yarn.lock',
}

# Ignore common binary/media extensions
EXCLUDE_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
    '.woff', '.woff2', '.ttf', '.eot',
    '.mp4', '.mp3', '.wav',
    '.pdf', '.zip', '.tar', '.gz'
)


def should_skip_file(file_name: str) -> bool:
    if file_name in EXCLUDE_FILES:
        return True
    if file_name.endswith(EXCLUDE_EXTENSIONS):
        return True
    return False


def dump_codebase(root_dir: str, output_file: str) -> None:
    with open(output_file, 'w', encoding='utf-8') as out:
        for dirpath, dirs, files in os.walk(root_dir):
            # Modify dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith('.')]

            for file_name in sorted(files):
                if should_skip_file(file_name):
                    continue

                file_path = os.path.join(dirpath, file_name)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                except Exception as e:
                    content = f"<Error reading file: {e}>"

                out.write("=" * 60 + "\n")
                out.write(f"File: {file_name}\n")
                out.write("=" * 60 + "\n\n")
                out.write(content)
                out.write("\n\n")

    print(f"Codebase dumped to: {output_file}")


if __name__ == "__main__":
    dump_codebase(ROOT_DIR, OUTPUT_FILE)
