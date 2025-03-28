import json
import keyring
import os
from dotenv import load_dotenv, find_dotenv
from pathlib import Path
from pydantic import BaseModel, Field, SecretStr
from typing import Any, Optional

from detectiq.core.integrations.elastic import ElasticCredentials
from detectiq.core.integrations.microsoft_xdr import MicrosoftXDRCredentials
from detectiq.core.integrations.splunk import SplunkCredentials
from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)

load_dotenv(find_dotenv())


class IntegrationCredentials(BaseModel):
    """Base integration credentials model."""

    hostname: str = Field(default="")
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    tenant_id: Optional[str] = None
    cloud_id: Optional[str] = None
    verify_ssl: bool = True
    enabled: bool = False

    class Config:
        extra = "allow"


class Integrations(BaseModel):
    """Integration configuration model."""

    splunk: Optional[SplunkCredentials] = None
    elastic: Optional[ElasticCredentials] = None
    microsoft_xdr: Optional[MicrosoftXDRCredentials] = None

    class Config:
        arbitrary_types_allowed = True


class DetectIQConfig(BaseModel):
    """Main configuration model."""

    openai_api_key: str = Field(default="")
    llm_model: str = Field(default="gpt-4o")
    embedding_model: str = Field(default="text-embedding-3-small")
    temperature: float = Field(default=round(float(os.getenv("LLM_TEMPERATURE", 0.10)), 2))
    rule_directories: dict = Field(
        default_factory=lambda: {
            "sigma": os.getenv("SIGMA_RULE_DIR", str(DEFAULT_DIRS.SIGMA_RULE_DIR)),
            "yara": os.getenv("YARA_RULE_DIR", str(DEFAULT_DIRS.YARA_RULE_DIR)),
            "snort": os.getenv("SNORT_RULE_DIR", str(DEFAULT_DIRS.SNORT_RULE_DIR)),
            "generated": os.getenv("GENERATED_RULE_DIR", str(DEFAULT_DIRS.GENERATED_RULE_DIR)),
        }
    )
    sigma_package_type: str = Field(default="core")
    vector_store_directories: dict = Field(
        default_factory=lambda: {
            "sigma": str(DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR),
            "yara": os.getenv("YARA_VECTOR_STORE_DIR", str(DEFAULT_DIRS.YARA_VECTOR_STORE_DIR)),
            "snort": os.getenv("SNORT_VECTOR_STORE_DIR", str(DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR)),
        }
    )
    log_level: str = Field(default="INFO")
    model: str = Field(default="gpt-4o")
    integrations: Integrations = Field(default_factory=Integrations)
    yara_package_type: str = Field(default="core")

    @property
    def RULE_DIRS(self):
        return self.rule_directories

    @property
    def VECTOR_STORE_DIRS(self):
        return self.vector_store_directories

    class Config:
        extra = "allow"


class ConfigManager:
    APP_NAME = "detectiq"
    PROJECT_ROOT = Path(DEFAULT_DIRS.BASE_DIR)
    CONFIG_FILE = Path(DEFAULT_DIRS.DATA_DIR) / "config.json"

    def __init__(self):
        logger.info(f"Initializing ConfigManager. Config file: {self.CONFIG_FILE}")
        self.config = self._load_config()
        if not self.CONFIG_FILE.exists():
            # Ensure parent directory exists
            self.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            self.save_config()

    def _load_config(self) -> DetectIQConfig:
        config_dict = self._get_default_config()
        if self.CONFIG_FILE.exists():
            self._update_from_file(config_dict)
        return DetectIQConfig(**config_dict)

    def _get_default_config(self) -> dict:
        try:
            openai_api_key = keyring.get_password(self.APP_NAME, "openai_api_key")
        except Exception as err:
            openai_api_key = os.getenv("OPENAI_API_KEY", "")

        return {
            "openai_api_key": openai_api_key,
            "llm_model": os.getenv("LLM_MODEL", "gpt-4o"),
            "temperature": round(float(os.getenv("LLM_TEMPERATURE", 0.10)), 2),
            "embedding_model": os.getenv("embedding_model", "text-embedding-3-small"),
            "rule_directories": {
                "sigma": os.getenv("SIGMA_RULE_DIR", str(DEFAULT_DIRS.SIGMA_RULE_DIR)),
                "yara": os.getenv("YARA_RULE_DIR", str(DEFAULT_DIRS.YARA_RULE_DIR)),
                "snort": os.getenv("SNORT_RULE_DIR", str(DEFAULT_DIRS.SNORT_RULE_DIR)),
                "generated": os.getenv("GENERATED_RULE_DIR", str(DEFAULT_DIRS.GENERATED_RULE_DIR)),
            },
            "vector_store_directories": {
                "sigma": os.getenv("SIGMA_VECTOR_STORE_DIR", str(DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR)),
                "yara": os.getenv("YARA_VECTOR_STORE_DIR", str(DEFAULT_DIRS.YARA_VECTOR_STORE_DIR)),
                "snort": os.getenv("SNORT_VECTOR_STORE_DIR", str(DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR)),
            },
            "log_level": os.getenv("DETECTIQ_LOG_LEVEL", "INFO"),
            "integrations": {},
            "sigma_package_type": os.getenv("SIGMA_PACKAGE_TYPE", "core"),
            "yara_package_type": os.getenv("YARA_PACKAGE_TYPE", "core"),
        }

    def save_config(self):
        config_dict = self.config.model_dump(exclude_none=True)
        with open(self.CONFIG_FILE, "w") as f:
            json.dump(config_dict, f, indent=2, default=str)

    def update_config(self, **kwargs):
        config_dict = self.config.model_dump()
        config_dict.update(kwargs)
        self.config = DetectIQConfig(**config_dict)
        self.save_config()

    def _update_from_file(self, config_dict: dict) -> None:
        with open(self.CONFIG_FILE) as f:
            file_config = json.load(f)

            # Ensure openai_api_key is a string if it exists in the file
            if "openai_api_key" in file_config and file_config["openai_api_key"] is None:
                file_config["openai_api_key"] = ""

            config_dict.update(file_config)


async def get_config(user: Optional[Any] = None) -> ConfigManager:
    """Get config manager instance."""
    return ConfigManager()
