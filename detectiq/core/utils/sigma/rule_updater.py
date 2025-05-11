import shutil
import zipfile
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiofiles
import aiohttp
from ruamel.yaml import YAML

from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class SigmaRuleUpdater:
    """Download/update Sigma rules from the official SigmaHQ release packages."""

    GITHUB_API_LATEST = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
    BASE_URL = "https://github.com/SigmaHQ/sigma/releases/latest/download"
    DRL_LICENSE_URL = (
        "https://raw.githubusercontent.com/SigmaHQ/Detection-Rule-License/refs/heads/main/LICENSE.Detection.Rules.md"
    )
    RULE_PACKAGES = {
        "core": "sigma_core.zip",
        "core+": "sigma_core+.zip",
        "core++": "sigma_core++.zip",
        "emerging_threats": "sigma_emerging_threats_addon.zip",
        "all": "sigma_all_rules.zip",
    }

    def __init__(self, rule_dir: Optional[str] = None, package_type: str = "core"):
        """Initialize SigmaRuleUpdater."""
        self.rule_dir = Path(rule_dir) if rule_dir else DEFAULT_DIRS.SIGMA_RULE_DIR
        self.rule_dir.mkdir(parents=True, exist_ok=True)

        if package_type not in self.RULE_PACKAGES:
            raise ValueError(f"Invalid package type. Must be one of: {list(self.RULE_PACKAGES.keys())}")
        self.package_type = package_type

        self.version_file = self.rule_dir / "version.txt"
        self.installed_version = self._read_installed_version()

        # Initialize YAML parser with roundtrip mode
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        self.yaml.width = 4096  # Prevent line wrapping

    def _read_installed_version(self) -> Optional[str]:
        if self.version_file.exists():
            with open(self.version_file, "r") as f:
                return f.read().strip()
        return None

    async def check_for_updates(self) -> Tuple[bool, Optional[str]]:
        """Check if updates are available."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.GITHUB_API_LATEST) as response:
                    response.raise_for_status()
                    latest_release = await response.json()
                    latest_version = latest_release["tag_name"]

                    if not self.installed_version or self.installed_version != latest_version:
                        return True, latest_version

                    return False, latest_version

        except Exception as e:
            raise RuntimeError(f"Failed to check for updates: {str(e)}")

    async def _save_drl_license(self) -> None:
        """Download and save the Detection Rule License."""
        try:
            # Create licenses directory if it doesn't exist - using DATA_DIR instead of BASE_DIR
            license_dir = Path(DEFAULT_DIRS.DATA_DIR) / Path("licenses/sigma")
            license_dir.mkdir(parents=True, exist_ok=True)

            # Download and save the DRL
            async with aiohttp.ClientSession() as session:
                async with session.get(self.DRL_LICENSE_URL) as response:
                    response.raise_for_status()
                    content = await response.text()

                    # Save to drl.md
                    async with aiofiles.open(license_dir / "drl.md", "w") as f:
                        await f.write(content)
                    logger.info(f"Saved Detection Rule License to {license_dir}/drl.md")

        except Exception as e:
            logger.error(f"Failed to save Detection Rule License: {e}")
            raise

    async def update_rules(self, force: bool = False) -> None:
        """Download and update rules."""
        try:
            updates_available, latest_version = await self.check_for_updates()

            if not updates_available and not force:
                logger.info("No updates available")
                return

            # Download DRL license first
            await self._save_drl_license()

            # Clean existing rules directory
            if self.rule_dir.exists():
                logger.info("Cleaning rule directory")
                try:
                    shutil.rmtree(self.rule_dir)
                    self.rule_dir.mkdir(parents=True, exist_ok=True)
                    logger.info("Successfully cleaned rule directory")
                except Exception as e:
                    logger.error(f"Error cleaning rule directory: {e}")
                    raise

            # Download and extract rules
            zip_url = f"{self.BASE_URL}/{self.RULE_PACKAGES[self.package_type]}"

            async with aiohttp.ClientSession() as session:
                async with session.get(zip_url) as response:
                    response.raise_for_status()
                    content = await response.read()

            # Extract rules
            with zipfile.ZipFile(BytesIO(content)) as zf:
                # Extract all YAML files
                for file_info in zf.filelist:
                    if file_info.filename.endswith(".yml"):
                        zf.extract(file_info, self.rule_dir)

            # Update installed version
            self.installed_version = latest_version
            if latest_version:
                with open(self.version_file, "w") as f:
                    f.write(latest_version)
                logger.info(f"Updated to version {latest_version}")
            else:
                logger.warning("No version information available")

        except Exception as e:
            raise RuntimeError(f"Failed to update rules: {str(e)}")

    async def load_rules(self) -> List[Dict[str, Any]]:
        """Load rules for vectorstore creation."""
        rules = []

        try:
            if not self.rule_dir.exists():
                logger.warning("Rules directory does not exist")
                return rules

            # Process each YAML file in the rules directory and its subdirectories
            for rule_file in self.rule_dir.glob("**/*.yml"):
                try:
                    with open(rule_file) as f:
                        rule_data = self.yaml.load(f)

                        # Skip non-rule files
                        if not isinstance(rule_data, dict) or "detection" not in rule_data:
                            continue

                        # Extract metadata
                        metadata = {
                            "title": rule_data.get("title", ""),
                            "id": rule_data.get("id", ""),
                            "status": rule_data.get("status", ""),
                            "description": rule_data.get("description", ""),
                            "author": rule_data.get("author", ""),
                            "rule_type": "sigma",
                            "package_type": self.package_type,
                            "version": self.installed_version,
                            "source": "SigmaHQ",
                        }

                        if "tags" in rule_data:
                            metadata["tags"] = rule_data["tags"]

                        if "logsource" in rule_data:
                            metadata["logsource"] = rule_data["logsource"]

                        severity = rule_data.get("level", "medium")

                        # Convert to string using ruamel.yaml
                        string_buffer = StringIO()
                        self.yaml.dump(rule_data, string_buffer)
                        rule_content = string_buffer.getvalue()

                        rules.append({"content": rule_content, "metadata": metadata, "severity": severity})

                except Exception as e:
                    logger.warning(f"Failed to process rule {rule_file}: {e}")
                    continue

            logger.info(f"Loaded {len(rules)} rules")

        except Exception as e:
            raise RuntimeError(f"Failed to load rules: {str(e)}")

        return rules
