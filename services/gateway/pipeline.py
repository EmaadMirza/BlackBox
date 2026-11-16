"""In-process gateway vertical slice with policy approvals and payload resolution."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from libs.blackbox_core import schemas
from libs.blackbox_core.chain import GENESIS_PREV_HASH
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash
from services.approval.verify import ApprovalVerificationError, ApprovalVerifier
from services.gateway.policy.engine import PolicyEngine
from services.gateway.tooldefs import ToolDefsRegistry
from services.payload_store.main import PayloadStore


class GatewayPipeline:
    def __init__(
        self,
        *,
        signer: Any,
        provider: Any,
        payload_store: PayloadStore,
        policy: PolicyEngine,
        agent_tokens: dict[str, str],
        clock: Callable[[], str],
        approval_verifier: ApprovalVerifier | None = None,
        tooldefs_registry: ToolDefsRegistry | None = None,
    ) -> None:
        self.signer = signer
        self.provider = provider
        self.payload_store = payload_store
        self.policy = policy
        self.agent_tokens = dict(agent_tokens)
        self.clock = clock
        self.approval_verifier = approval_verifier
        self.tooldefs_registry = tooldefs_registry
        self._retries: dict[str, dict[str, object]] = {}

    def execute(
        self,
        agent_id: str,
        delegation_token: str,
        tool_name: str,
        body: bytes,
        idempotency_key: str,
        *,
        context: schemas.Context | None = None,
        approval_receipt: schemas.ApprovalReceipt | None = None,
        approval_receipt_signer: Callable[[schemas.Intent, str], schemas.ApprovalReceipt]
        | None = None,
        denial_reason: str | None = None,
        salt: bytes | None = None,
        session_id: str | None = None,
    ) -> dict[str, object]:
        if self.agent_tokens.get(agent_id) != delegation_token:
            raise PermissionError("agent authentication failed")
        if idempotency_key in self._retries:
            return self._retries[idempotency_key]

        # Check tool definitions change if registry and context provided
        if (
            self.tooldefs_registry is not None
            and session_id is not None
            and context is not None
            and context.tool_definitions_hash
        ):
            if self.tooldefs_registry.is_changed(session_id, context.tool_definitions_hash):
                body_digest = encode_hash(sha256(body))
                reference, commitment = self.payload_store.put(body, salt=salt)
                principal = schemas.Principal(
                    client_key_id=agent_id,
                    source_address="gateway",
                    human_identity=agent_id,
                    agent_identity=agent_id,
                    agent_version="1",
                    delegation_chain=[delegation_token],
                )
                action = schemas.RequestAction(
                    adapter="http",
                    method="POST",
                    path=f"/{tool_name}",
                    tool_name=tool_name,
                    body_digest=body_digest,
                    arguments_commitment=commitment,
                    idempotency_key=idempotency_key,
                    payload_reference=reference,
                )
                decision = self.policy.evaluate(action, principal)
                timestamp = self.clock()
                blocked = schemas.Blocked(
                    format_version="4",
                    log_id="sha256:" + "0" * 64,
                    epoch_id=0,
                    seq=0,
                    signer_timestamp=timestamp,
                    prev_hash=GENESIS_PREV_HASH,
                    lane="web",
                    epoch_certificate_id="sha256:" + "0" * 64,
                    principal=principal,
                    action=action,
                    policy=decision,
                    context=context,
                    reason="TOOL_DEF_CHANGE",
                    claimed_time=timestamp,
                    type="blocked",
                )
                sealed = self.signer.seal(blocked)
                result = {
                    "status": "blocked",
                    "intent_seq": getattr(getattr(sealed, "body", sealed), "seq", 0),
                    "evidence": {"reason": "TOOL_DEF_CHANGE"},
                    "blocked": sealed,
                }
                self._retries[idempotency_key] = result
                return result
        body_digest = encode_hash(sha256(body))
        reference, commitment = self.payload_store.put(body, salt=salt)

        amount_minor = None
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and isinstance(parsed.get("amount_minor"), int):
                amount_minor = parsed["amount_minor"]
        except Exception:
            pass

        principal = schemas.Principal(
            client_key_id=agent_id,
            source_address="gateway",
            human_identity=agent_id,
            agent_identity=agent_id,
            agent_version="1",
            delegation_chain=[delegation_token],
        )
        action = schemas.RequestAction(
            adapter="http",
            method="POST",
            path=f"/{tool_name}",
            tool_name=tool_name,
            body_digest=body_digest,
            arguments_commitment=commitment,
            idempotency_key=idempotency_key,
            payload_reference=reference,
            amount_minor=amount_minor,
        )
        decision = self.policy.evaluate(action, principal)
        timestamp = self.clock()
        common = dict(
            format_version="4",
            log_id="sha256:" + "0" * 64,
            epoch_id=0,
            seq=0,
            signer_timestamp=timestamp,
            prev_hash=GENESIS_PREV_HASH,
            lane="web",
            epoch_certificate_id="sha256:" + "0" * 64,
            principal=principal,
            action=action,
            policy=decision,
            context=context,
            claimed_time=timestamp,
        )

        if decision.decision == "block":
            blocked = schemas.Blocked(**common, type="blocked", reason=decision.matching_rule_id)
            sealed = self.signer.seal(blocked)
            result = {
                "status": "blocked",
                "intent_seq": getattr(getattr(sealed, "body", sealed), "seq", 0),
                "evidence": {"reason": decision.matching_rule_id},
                "blocked": sealed,
            }
            self._retries[idempotency_key] = result
            return result

        if decision.decision == "require_approval":
            # 1. Seal intent with status="pending"
            pending_intent = schemas.Intent(**common, type="intent", status="pending")
            sealed_pending = self.signer.seal(pending_intent)
            intent_body = getattr(sealed_pending, "body", sealed_pending)

            if (
                approval_receipt_signer is not None
                and approval_receipt is None
                and not denial_reason
            ):
                approval_receipt = approval_receipt_signer(intent_body, commitment)

            # 2. Check denial or missing receipt
            if denial_reason or approval_receipt is None:
                reason = denial_reason or "approval_required"
                blocked = schemas.Blocked(**common, type="blocked", reason=reason)
                sealed_blocked = self.signer.seal(blocked)
                result = {
                    "status": "blocked",
                    "intent_seq": getattr(intent_body, "seq", 0),
                    "evidence": {"reason": reason},
                    "intent": sealed_pending,
                    "blocked": sealed_blocked,
                }
                self._retries[idempotency_key] = result
                return result

            # 3. Verify approval receipt
            if self.approval_verifier is not None:
                try:
                    self.approval_verifier.verify(
                        approval_receipt, principal.agent_identity, commitment
                    )
                except ApprovalVerificationError as exc:
                    reason = str(exc)
                    blocked = schemas.Blocked(**common, type="blocked", reason=reason)
                    sealed_blocked = self.signer.seal(blocked)
                    result = {
                        "status": "blocked",
                        "intent_seq": getattr(intent_body, "seq", 0),
                        "evidence": {"reason": reason},
                        "intent": sealed_pending,
                        "blocked": sealed_blocked,
                    }
                    self._retries[idempotency_key] = result
                    return result

            # 4. Seal approval entry
            approval_entry = schemas.Approval(
                format_version="4",
                log_id=common["log_id"],
                epoch_id=common["epoch_id"],
                seq=0,
                signer_timestamp=timestamp,
                prev_hash=common["prev_hash"],
                lane=common["lane"],
                epoch_certificate_id=common["epoch_certificate_id"],
                type="approval",
                receipt=approval_receipt,
            )
            sealed_approval = self.signer.seal(approval_entry)

            # 5. Proceed to provider
            attestation = self.signer.attest(intent_body)
            header = {"X-BlackBox-Attestation": json.dumps(attestation, separators=(",", ":"))}
            provider_result = self.provider.request(body, header)
            result_value = provider_result.get("result", b"")
            result_ref, result_commitment = self.payload_store.put(result_value)
            outcome_data = {**common, "type": "outcome", "seq": 1, "prev_hash": GENESIS_PREV_HASH}
            outcome = schemas.Outcome(
                **outcome_data,
                intent_seq=getattr(intent_body, "seq", 0),
                retry=False,
                upstream_status=int(provider_result["status"]),
                result_commitment=result_commitment,
                provider_request_id=str(provider_result["request_id"]),
                latency=0,
            )
            sealed_outcome = self.signer.seal(outcome)
            result = {
                "status": "ok" if provider_result["status"] < 400 else "failed",
                "intent_seq": getattr(intent_body, "seq", 0),
                "outcome_seq": getattr(getattr(sealed_outcome, "body", sealed_outcome), "seq", 1),
                "evidence": {"payload_reference": reference, "result_reference": result_ref},
                "intent": sealed_pending,
                "approval": sealed_approval,
                "outcome": sealed_outcome,
            }
            self._retries[idempotency_key] = result
            return result

        intent = schemas.Intent(**common, type="intent", status="ready")
        sealed_intent = self.signer.seal(intent)
        intent_body = getattr(sealed_intent, "body", sealed_intent)
        attestation = self.signer.attest(intent_body)
        header = {"X-BlackBox-Attestation": json.dumps(attestation, separators=(",", ":"))}
        provider_result = self.provider.request(body, header)
        result_value = provider_result.get("result", b"")
        result_ref, result_commitment = self.payload_store.put(result_value)
        outcome_data = {**common, "type": "outcome", "seq": 1, "prev_hash": GENESIS_PREV_HASH}
        outcome = schemas.Outcome(
            **outcome_data,
            intent_seq=getattr(intent_body, "seq", 0),
            retry=False,
            upstream_status=int(provider_result["status"]),
            result_commitment=result_commitment,
            provider_request_id=str(provider_result["request_id"]),
            latency=0,
        )
        sealed_outcome = self.signer.seal(outcome)
        result = {
            "status": "ok" if provider_result["status"] < 400 else "failed",
            "intent_seq": getattr(intent_body, "seq", 0),
            "outcome_seq": getattr(getattr(sealed_outcome, "body", sealed_outcome), "seq", 1),
            "evidence": {"payload_reference": reference, "result_reference": result_ref},
            "intent": sealed_intent,
            "outcome": sealed_outcome,
        }
        self._retries[idempotency_key] = result
        return result


async def execute(
    action: schemas.RequestAction, principal: schemas.Principal, context: schemas.Context | None
) -> bytes:
    raise NotImplementedError("use GatewayPipeline with injected in-process components")
