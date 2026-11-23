from guardian.ai import state
from guardian.models import FindingsArtifact, FixAction, RemediationProposal


def test_proposal_models_live_in_shared_contract_and_state_reexports_them() -> None:
    assert state.FixAction is FixAction
    assert state.RemediationProposal is RemediationProposal


def test_findings_artifact_round_trips_proposals() -> None:
    proposal = RemediationProposal(
        proposal_id="p1", finding_id="f1", action=FixAction.UPGRADE, target_version="2.0.0",
        rationale="Fixes CVE-1.", rollback="Revert to 1.0.0.", breaking_change_risk="low",
        evidence_ids=[],
    )
    artifact = FindingsArtifact(proposals=[proposal])
    assert FindingsArtifact.model_validate_json(artifact.model_dump_json()).proposals == [proposal]
    assert FindingsArtifact().proposals == []
