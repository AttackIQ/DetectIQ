import io
import os
import shutil
import zipfile
from pathlib import Path

import requests

from detectiq.sigmaiq.globals import DEFAULT_DIRS


class SigmaRuleUpdater:
    """Download/update Sigma rules from the official SigmaHQ release packages."""

    PACKAGE_NAME_URIS = {
        "core": "sigma_core.zip",
        "core+": "sigma_core+.zip",
        "core++": "sigma_core++.zip",
        "emerging_threats": "sigma_emerging_threats_addon.zip",
        "all": "sigma_all_rules.zip",
    }

    BASE_DOWNLOAD_URL = "https://github.com/SigmaHQ/sigma/releases/download"

    def __init__(self, rule_dir: str = None):
        self.rule_dir = setup_rule_dir(rule_dir)
        self.installed_tag = self._get_installed_release_tag()
        self.latest_tag = get_latest_sigma_release_tag()

    def _get_installed_release_tag(self) -> str:
        """Returns the currently installed Sigma release tag by checking the directory name of the
        SIGMA_RULE_DIR directory.

        Returns:
            str: The currently installed Sigma release tag, or "" if not found.
        """
        version_file = Path(self.rule_dir) / "version.txt"
        if not version_file.exists():
            return ""
        with open(version_file, "r") as f:
            current_version = "r" + f.readlines()[0].split(": ")[-1].strip()
        return current_version

    def _needs_update(self) -> bool:
        """Checks if the currently installed Sigma release tag is the same as the latest release tag.

        Returns:
            bool: True if the latest_tag is different from the currently installed release tag, False otherwise.
        """
        if not self.installed_tag:
            return True
        return self.latest_tag != self.installed_tag

    def update_sigma_rules(
        self,
        force: bool = False,
        package_name: str = "core",
        emerging_threats: bool = False,
    ):
        """Downloads the latest Sigma release package, if needed, and extracts it to the SIGMA_RULE_DIR directory.

        Args:
            force (bool, optional): If True, will always download the latest Sigma release package. Defaults to False.
            package_name (str, optional): The name of the Sigma release package to download. Defaults to "core". Valid
            options are "core", "core+", "core++", "emerging_threats", and "all"
            emerging_threats (bool, optional): If True, will download the emerging_threats Sigma release package in
            addition to the package specified in args. Defaults to False.

        Raises:
            ValueError: If the package_name is invalid.


        """
        if package_name not in self.PACKAGE_NAME_URIS.keys():
            raise ValueError(f"Invalid package name '{package_name}'. Valid options are: {self.PACKAGE_NAME_URIS.keys}")

        print(f"Installed Sigma release tag at {self.rule_dir}: {self.installed_tag}")
        if not self._needs_update() and not force:
            print("Sigma rules are up-to-date.")
            return
        print(f"Updating Sigma rules to {self.latest_tag}...")
        self._download_sigma_release(package_name)

        if emerging_threats:
            if package_name in ["emerging_threats", "all"]:
                print("emerging-threats already contains in the selected package, skipping download.")
            else:
                print("Downloading emerging_threats Sigma rules...")
                self._download_sigma_release("emerging_threats", overwrite=False)
        print("Sigma rules up to date!")

    def _download_sigma_release(self, package_name: str, overwrite: bool = True):
        """Downloads the latest Sigma release package and extracts it to the SIGMA_RULE_DIR directory.

        Args:
            package_name (str): The name of the Sigma release package to download. Valid options are "core", "core+",
            "core++", "emerging_threats", and "all"
            overwrite (bool, optional): If True, will overwrite the currently installed Sigma release package. Defaults
            to True.

        Raises:
            ValueError: If the package_name is invalid.
        """
        if overwrite:
            print(f"Removing Sigma rules at {self.rule_dir} before new download...")
            shutil.rmtree(os.path.join(self.rule_dir, "rules"), ignore_errors=True)
            shutil.rmtree(os.path.join(self.rule_dir, "rules-emerging-threats"), ignore_errors=True)

        if package_name not in self.PACKAGE_NAME_URIS.keys():
            raise ValueError(f"Invalid package name '{package_name}'. Valid options are: {self.PACKAGE_NAME_URIS.keys}")

        url = f"{self.BASE_DOWNLOAD_URL}/{self.latest_tag}/{self.PACKAGE_NAME_URIS[package_name]}"
        r = requests.get(url, allow_redirects=True)
        if not r.ok:
            raise Exception(f"Error downloading Sigma release package: {r.url} {r.status_code} - {r.reason}")
        self._extract_sigma_release(r.content)

    def _extract_sigma_release(self, content: bytes):
        """Extracts the Sigma release package to the SIGMA_RULE_DIR directory.

        Args:
            content (bytes): The content of the Sigma release package.
        """

        zf = zipfile.ZipFile(io.BytesIO(content))
        zf.extractall(self.rule_dir)
        print(f"Extracted Sigma release package to {self.rule_dir}")


def get_latest_sigma_release_tag():
    """Requests https://github.com/SigmaHQ/sigma/releases/latest and returns the URL of the response
    as the latest release
    """
    url = "https://github.com/SigmaHQ/sigma/releases/latest"
    r = requests.get(url, allow_redirects=False)
    if not r.ok:
        raise Exception(f"Error getting latest Sigma release: {r.url} {r.status_code} - {r.reason}")
    latest_tag = r.next.path_url.split("/")[-1]
    if not latest_tag:
        raise Exception(f"Error getting latest Sigma release: {r.url} {r.status_code} - {r.reason}")
    return latest_tag


def setup_rule_dir(rule_dir: str) -> str:
    """Creates the SIGMA_RULE_DIR directory if it doesn't exist, and returns the path to the directory.

    Args:
        rule_dir (str): The path to a directory where Sigma rules should be installed.

    Returns:
        str: The path to the SIGMA_RULE_DIR directory.
    """
    if not rule_dir:
        rule_dir = DEFAULT_DIRS.SIGMA_RULE_DIR
    if not os.path.exists(rule_dir):
        os.makedirs(rule_dir)
    return rule_dir
