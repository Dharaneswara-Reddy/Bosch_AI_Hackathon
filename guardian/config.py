"""Read Guardian settings from a local dotenv file and the environment."""

import os
from pathlib import Path

from pydantic import BaseModel, Field, SecretStr, model_validator

AI_TOP_N = 20
TOOL_TIMEOUT_S = 180


class Settings(BaseModel):
    provider: str = "none"
    api_key: SecretStr = Field(default_factory=lambda: SecretStr(""))
    model: str = ""
    timeout_s: int = Field(default=30, gt=0)
    tool_images: dict[str, str] = Field(default_factory=dict)
    db_built_at: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_provider_key(self) -> "Settings":
        if self.provider != "none" and not self.api_key.get_secret_value().strip():
            raise ValueError("Set GUARDIAN_LLM_API_KEY for the configured provider, or use --no-llm.")
        return self

    @classmethod
    def load(cls, *, use_llm: bool = True, dotenv: Path = Path(".env")) -> "Settings":
        values: dict[str, str] = {}
        if dotenv.is_file():
            for line in dotenv.read_text(encoding="utf-8").splitlines():
                key, sep, value = line.strip().partition("=")
                if sep and key and not key.startswith("#"):
                    values[key.strip()] = value.strip().strip('"').strip("'")
        values.update(os.environ)
        names = ("syft", "grype", "osv")
        return cls.model_validate({
            "provider": values.get("GUARDIAN_LLM_PROVIDER", "none") if use_llm else "none",
            "api_key": values.get("GUARDIAN_LLM_API_KEY", ""),
            "model": values.get("GUARDIAN_LLM_MODEL", ""),
            "timeout_s": values.get("GUARDIAN_LLM_TIMEOUT_S", "30"),
            "tool_images": {
                name: values[f"GUARDIAN_{name.upper()}_IMAGE"] for name in names
                if f"GUARDIAN_{name.upper()}_IMAGE" in values
            },
            "db_built_at": {
                name: values[f"GUARDIAN_{name.upper()}_DB_BUILT_AT"] for name in names
                if f"GUARDIAN_{name.upper()}_DB_BUILT_AT" in values
            },
        })
