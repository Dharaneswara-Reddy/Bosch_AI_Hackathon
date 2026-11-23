from pathlib import Path

import pytest
from pydantic import ValidationError

from guardian.config import Settings


def test_llm_key_only_required_for_enabled_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GUARDIAN_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("GUARDIAN_LLM_API_KEY", raising=False)
    dotenv = tmp_path / ".env"
    dotenv.write_text("GUARDIAN_LLM_PROVIDER=provider\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="GUARDIAN_LLM_API_KEY"):
        Settings.load(dotenv=dotenv)
    assert Settings.load(use_llm=False, dotenv=dotenv).provider == "none"
