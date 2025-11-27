import os
import hashlib
import json
import sys

# Configuration
# Scans the user's home directory
SEARCH_DIR = os.path.expanduser("~")

# Known malicious filenames associated with Shai-Hulud 2.0
TARGET_FILENAMES = {
    'setup_bun.js',
    'bun_environment.js',
    'cloud.json',
    'contents.json',
    'environment.json',
    'truffleSecrets.json'
}

# SHA256 hashes of known malicious 'bun_environment.js' payloads
MALICIOUS_HASHES = {
    '62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0',
    'f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068'
}

# Known malicious workflow filenames
SUSPICIOUS_WORKFLOWS = {
    'discussion.yaml',
}

def calculate_sha256(filepath):
    """Calculates the SHA256 hash of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            # Read in 4KB chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, OSError):
        return None

def check_package_json(filepath):
    """Checks package.json for the malicious preinstall script."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            scripts = data.get('scripts', {})
            preinstall = scripts.get('preinstall', '')
            # The attack typically runs 'node setup_bun.js'
            if 'setup_bun.js' in preinstall:
                return True
    except (json.JSONDecodeError, PermissionError, OSError, UnicodeDecodeError):
        pass
    return False

def scan():
    print(f"Starting scan of {SEARCH_DIR}...")
    print("This may take a while depending on the number of files.")
    print("Scanning for:")
    print(f" - Files: {', '.join(TARGET_FILENAMES)}")
    print(f" - Malicious package.json preinstall scripts")
    print(f" - Suspicious GitHub workflows\n")
    
    found_threats = []
    files_scanned = 0

    for root, dirs, files in os.walk(SEARCH_DIR):
        # Optimization: Skip system Library directories to reduce noise and permission errors
        if 'Library' in root.split(os.sep):
             continue
        
        # Modify dirs in-place to skip hidden directories if desired (optional, but scanning all for safety)
        # dirs[:] = [d for d in dirs if not d.startswith('.')] 

        for file in files:
            filepath = os.path.join(root, file)
            files_scanned += 1
            
            # Check 1: Malicious Filenames
            if file in TARGET_FILENAMES:
                if file == 'bun_environment.js':
                    file_hash = calculate_sha256(filepath)
                    if file_hash in MALICIOUS_HASHES:
                         found_threats.append(f"[CRITICAL] Malicious bun_environment.js found at {filepath} (Hash match)")
                    else:
                         found_threats.append(f"[WARNING] Suspicious file found (name match): {filepath} (Hash: {file_hash})")
                else:
                    found_threats.append(f"[WARNING] Suspicious file found: {filepath}")

            # Check 2: GitHub Workflows
            if file in SUSPICIOUS_WORKFLOWS or (file.startswith('formatter_') and file.endswith('.yml')):
                if '.github/workflows' in filepath:
                     found_threats.append(f"[HIGH] Suspicious GitHub workflow found: {filepath}")

            # Check 3: package.json preinstall
            if file == 'package.json':
                if check_package_json(filepath):
                    found_threats.append(f"[HIGH] Malicious 'preinstall' script detected in {filepath}")

    print(f"\nScanned {files_scanned} files.")
    return found_threats

if __name__ == "__main__":
    try:
        threats = scan()
        
        print("\n" + "="*30)
        print("SCAN COMPLETE")
        print("="*30)
        
        if threats:
            print("\n!!! POTENTIAL THREATS DETECTED !!!")
            for threat in threats:
                print(threat)
        else:
            print("\nNo specific IoCs for Shai-Hulud 2.0 were found in the scanned paths.")
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
