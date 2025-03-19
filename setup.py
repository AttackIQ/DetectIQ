import os
import subprocess

from setuptools import find_packages, setup
from setuptools.command.install import install


def build_frontend():
    """Build frontend as part of package installation."""
    script_path = os.path.join("detectiq", "scripts", "build_frontend.py")
    if os.path.exists(script_path):
        subprocess.run(["python", script_path], check=True)


class CustomInstallCommand(install):
    """Custom install command to build frontend."""

    def run(self):
        build_frontend()
        super().run()


# Core requirements that are always needed
with open("requirements/core.txt") as f:
    core_requirements = f.read().splitlines()

# Optional integration-specific requirements
with open("requirements/splunk.txt") as f:
    splunk_requirements = f.read().splitlines()

with open("requirements/elastic.txt") as f:
    elastic_requirements = f.read().splitlines()

with open("requirements/microsoft.txt") as f:
    microsoft_requirements = f.read().splitlines()

# Analysis tool requirements
analysis_requirements = [
    "pefile>=2023.2.7",
    "yara-python>=4.3.1",
    "scapy>=2.5.0",
    "python-magic>=0.4.27",  # For better file type detection
]

# Development requirements
dev_requirements = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.23.0",
    "black>=23.0.0",
    "isort>=5.12.0",
    "mypy>=1.0.0",
]

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="detectiq",
    version="0.1.0",
    author="AttackIQ",
    author_email="rajesh.sharma@attackiq.com",
    description="A detection engineering workbench with LLM capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AttackIQ/DetectIQ",
    project_urls={
        "Bug Tracker": "https://github.com/AttackIQ/DetectIQ/issues",
        "Documentation": "https://github.com/AttackIQ/DetectIQ",
        "Source Code": "https://github.com/AttackIQ/DetectIQ",
    },
    packages=find_packages(),
    install_requires=core_requirements,
    extras_require={
        "splunk": splunk_requirements,
        "elastic": elastic_requirements,
        "microsoft": microsoft_requirements,
        "analysis": analysis_requirements,
        "dev": dev_requirements,
        "all": (splunk_requirements + elastic_requirements + microsoft_requirements + analysis_requirements),
        "full": (  # Everything including dev dependencies
            splunk_requirements
            + elastic_requirements
            + microsoft_requirements
            + analysis_requirements
            + dev_requirements
        ),
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
    cmdclass={
        "install": CustomInstallCommand,
    },
    include_package_data=True,
    package_data={
        "detectiq": ["webapp/backend/static/*"],
    },
)
