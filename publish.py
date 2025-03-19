#!/usr/bin/env python3
"""
Script to build and publish the package to PyPI.
"""
import os
import subprocess
import sys


def run_command(command):
    """Run a shell command and handle errors."""
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(f"Error details: {e}")
        sys.exit(1)


def main():
    """Main function to build and publish the package."""
    # Ensure we have the latest pip, setuptools, wheel, and twine
    print("Upgrading build tools...")
    run_command("pip install --upgrade pip setuptools wheel twine build")
    
    # Clean up previous builds
    print("Cleaning up previous builds...")
    if os.path.exists("dist"):
        run_command("rm -rf dist/*")
    
    # Build the package
    print("Building the package...")
    run_command("python -m build")
    
    # Check the distribution
    print("Checking the distribution...")
    run_command("twine check dist/*")
    
    # Upload to PyPI (or TestPyPI)
    upload = input("Do you want to upload to PyPI? (yes/no/test): ").lower()
    
    if upload == "yes":
        print("Uploading to PyPI...")
        run_command("twine upload dist/*")
    elif upload == "test":
        print("Uploading to TestPyPI...")
        run_command("twine upload --repository-url https://test.pypi.org/legacy/ dist/*")
    else:
        print("Skipping upload. Distribution files are in the 'dist' directory.")
    
    print("Done!")


if __name__ == "__main__":
    main() 