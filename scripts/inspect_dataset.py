import os

ARCHIVE_DIR = "archive"

def inspect_file_raw(filename, nlines=6):
    filepath = os.path.join(ARCHIVE_DIR, filename)
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return
    print(f"\n=== Inspecting {filename} (First {nlines} lines) ===")
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for i in range(nlines):
                line = f.readline()
                if not line:
                    break
                print(f"{i+1}: {line.strip()}")
    except Exception as e:
        print(f"Error reading file: {e}")

if __name__ == "__main__":
    inspect_file_raw("HI-Small_accounts.csv")
    inspect_file_raw("HI-Small_Trans.csv")
