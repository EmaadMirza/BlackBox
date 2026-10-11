"""Offline full-prefix verification with externally pinned trust (spec §16.3)."""

from __future__ import annotations

from pathlib import Path

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.checkpoint import verify_checkpoint, verify_cosignature
from libs.blackbox_core.commitments import verify_opening
from libs.blackbox_core.encoding import decode_base64url, decode_hash
from libs.blackbox_core.epochs import certificate_id, validate_contiguity, verify_epoch_certificate
from libs.blackbox_core.evidence import Bundle, PinnedKeys
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.merkle import MerkleTree, leaf_hash, verify_consistency, verify_inclusion
from libs.blackbox_core.schemas import EpochEnd, EpochStart, Outcome, SealedEntry
from libs.blackbox_core.sealing import sealed_bytes, verify_entry
from libs.blackbox_core.signing import structure_hash, verify_structure
from libs.blackbox_core.witness_set import has_quorum, verify_witness_set
from tools.verifier.bundle_loader import load_bundle, load_pinned_keys
from tools.verifier.verdicts import EntryVerdict, VerificationReport

MAX_ENTRIES = 100_000


def verify_bundle(bundle_path: Path, pinned_keys_path: Path) -> VerificationReport:
    return verify_evidence(load_bundle(bundle_path), load_pinned_keys(pinned_keys_path))


def verify_evidence(bundle: Bundle, pins: PinnedKeys) -> VerificationReport:
    """Verifies only evidence supplied; trusted minimum size prevents known rollback."""
    bundle = Bundle.model_validate(bundle)
    pins = PinnedKeys.model_validate(pins)
    if len(bundle.entries) > MAX_ENTRIES:
        raise ValueError("bundle exceeds entry limit")
    results: dict[int, EntryVerdict] = {}
    parsed: dict[int, SealedEntry] = {}
    order = []

    def mark(seq: int, verdict: str, reason: str) -> None:
        results.setdefault(seq, EntryVerdict(seq)).add(verdict, reason)

    def all_mark(verdict: str, reason: str) -> None:
        for seq in list(results) or [0]:
            mark(seq, verdict, reason)

    for index, raw in enumerate(bundle.entries):
        body = raw.get("body", {})
        seq = body.get("seq", index) if isinstance(body, dict) else index
        if type(seq) is not int or not 0 <= seq < MAX_ENTRIES:
            seq = index
        results.setdefault(seq, EntryVerdict(seq))
        try:
            entry = SealedEntry.model_validate(raw)
        except ValueError:
            mark(seq, "TAMPERED", "entry schema invalid")
            continue
        if entry.body.seq >= MAX_ENTRIES:
            raise ValueError("sequence exceeds verification resource limit")
        seq = entry.body.seq
        order.append(seq)
        if seq in parsed:
            mark(seq, "TAMPERED", "duplicate sequence")
        else:
            parsed[seq] = entry
    for actual, expected_seq in zip(order, sorted(order)):
        if actual != expected_seq:
            mark(actual, "TAMPERED", "entry order is not increasing")
    root_key = decode_base64url(pins.root_public_key)
    identity_ok = (
        bundle.log_id == pins.log_id
        and bundle.log_name == pins.log_name
        and derive_log_id(root_key, pins.log_name) == pins.log_id
    )
    if not identity_ok:
        all_mark("TAMPERED", "log identity differs from pinned root/name")
    intermediates = {cert.intermediate_id: cert for cert in bundle.intermediates}
    epochs = {cert.epoch_id: cert for cert in bundle.epochs}
    if len(intermediates) != len(bundle.intermediates) or len(epochs) != len(bundle.epochs):
        all_mark("TAMPERED", "duplicate certificate identity")
    revocations = [*pins.revocations, *bundle.revocations]
    for revocation in revocations:
        if revocation.log_id != pins.log_id or not verify_structure(
            revocation, root_key, "revocation"
        ):
            all_mark("TAMPERED", "invalid root-signed revocation")
    for cert in bundle.intermediates:
        if cert.log_id != pins.log_id or not verify_structure(cert, root_key, "intermediate_cert"):
            all_mark("TAMPERED", "invalid intermediate certificate signature/log")
    sorted_epochs = sorted(epochs.values(), key=lambda cert: cert.epoch_id)
    for i, cert in enumerate(sorted_epochs):
        if i == 0 and cert.epoch_id != 0:
            all_mark("TAMPERED", "full-prefix epoch chain must begin at zero")
        if i:
            try:
                validate_contiguity(sorted_epochs[i - 1], cert)
            except ValueError:
                all_mark("TAMPERED", "non-contiguous epoch certificates")
        issuer = intermediates.get(cert.intermediate_id)
        if (
            cert.log_id != pins.log_id
            or issuer is None
            or not verify_epoch_certificate(cert, issuer, root_key, cert.valid_from)
        ):
            all_mark("TAMPERED", "invalid epoch certificate chain")

    def valid_cert(epoch_id: int, stamp: str) -> bool:
        cert = epochs.get(epoch_id)
        issuer = intermediates.get(cert.intermediate_id) if cert else None
        return (
            cert is not None
            and issuer is not None
            and cert.log_id == pins.log_id
            and verify_epoch_certificate(cert, issuer, root_key, stamp, revocations)
        )

    # Per-entry checks precede tree diagnostics, so signature failure is the first reason.
    for seq, entry in parsed.items():
        body = entry.body
        cert = epochs.get(body.epoch_id)
        if body.log_id != pins.log_id:
            mark(seq, "TAMPERED", "entry from another log")
        if not valid_cert(body.epoch_id, body.signer_timestamp):
            mark(seq, "TAMPERED", "certificate chain, epoch validity or revocation failed")
        if cert is None or body.epoch_certificate_id != certificate_id(cert):
            mark(seq, "TAMPERED", "epoch certificate reference mismatch")
        if cert is not None and not verify_entry(entry, decode_base64url(cert.epoch_public_key)):
            mark(seq, "TAMPERED", "entry signature failure")
        if seq == 0 and body.prev_hash != GENESIS_PREV_HASH:
            mark(seq, "TAMPERED", "genesis hash mismatch")
        if seq - 1 in parsed:
            previous = parsed[seq - 1].body
            if body.prev_hash != entry_hash(previous):
                mark(seq, "TAMPERED", "previous hash mismatch")
            if body.signer_timestamp < previous.signer_timestamp:
                mark(seq, "TAMPERED", "signer timestamp decreased")
            if body.epoch_id != previous.epoch_id and (
                body.epoch_id != previous.epoch_id + 1
                or not isinstance(body, EpochStart)
                or not isinstance(previous, EpochEnd)
            ):
                mark(seq, "TAMPERED", "epoch transition lacks contiguous end/start")
            if body.epoch_id == previous.epoch_id and isinstance(previous, EpochEnd):
                mark(seq, "TAMPERED", "entry after epoch_end")
            if body.epoch_id == previous.epoch_id and isinstance(body, EpochStart):
                mark(seq, "TAMPERED", "duplicate epoch_start")
        if isinstance(body, EpochStart) and (cert is None or body.certificate != cert):
            mark(seq, "TAMPERED", "epoch_start certificate mismatch")
        if isinstance(body, Outcome) and body.intent_seq in parsed:
            intent = parsed[body.intent_seq].body
            if (
                intent.type != "intent"
                or intent.seq >= seq
                or intent.action.idempotency_key != body.action.idempotency_key
            ):
                mark(seq, "TAMPERED", "outcome intent reference invalid")
    if 0 in parsed and not isinstance(parsed[0].body, EpochStart):
        mark(0, "TAMPERED", "first entry must be epoch_start")
    ws = bundle.witness_set
    trusted_set = (
        ws.log_id == pins.log_id
        and verify_witness_set(ws, root_key)
        and {w.witness_id: w.public_key for w in ws.witnesses} == pins.witness_public_keys
    )
    if not trusted_set:
        all_mark("TAMPERED", "witness set differs from pinned identities or invalid root signature")
    checkpoints = []
    witnessed = []
    for evidence in bundle.checkpoints:
        cp = evidence.checkpoint
        cert = epochs.get(cp.epoch_id)
        if cp.tree_size > MAX_ENTRIES:
            raise ValueError("checkpoint size exceeds verification resource limit")
        if (
            cp.log_id != pins.log_id
            or not valid_cert(cp.epoch_id, cp.signer_timestamp)
            or cert is None
            or not verify_checkpoint(cp, decode_base64url(cert.epoch_public_key))
        ):
            all_mark("TAMPERED", "checkpoint signature or certificate invalid")
            continue
        latest = parsed.get(cp.latest_seq)
        if latest is not None and (
            cp.signer_timestamp < latest.body.signer_timestamp
            or cp.epoch_id != latest.body.epoch_id
        ):
            all_mark("TAMPERED", "checkpoint state predates its latest entry")
        for cosig in evidence.cosignatures:
            public = pins.witness_public_keys.get(cosig.witness_id)
            if (
                public is None
                or cosig.log_id != cp.log_id
                or cosig.checkpoint_hash != structure_hash(cp)
                or cosig.witness_timestamp < cp.signer_timestamp
                or not verify_cosignature(cosig, decode_base64url(public))
            ):
                all_mark("TAMPERED", "invalid witness cosignature or checkpoint binding")
        checkpoints.append(cp)
        if trusted_set and has_quorum(cp, evidence.cosignatures, ws):
            witnessed.append(cp)
    # An epoch-signed checkpoint is authenticated size evidence even without quorum.
    expected = max(
        [pins.minimum_tree_size, max(parsed, default=-1) + 1] + [cp.tree_size for cp in checkpoints]
    )
    if expected > MAX_ENTRIES:
        raise ValueError("trusted size exceeds verification resource limit")
    for seq in range(expected):
        if seq not in parsed and seq not in results:
            mark(seq, "MISSING", "sequence absent from authenticated or observed log range")
    if not results:
        mark(0, "UNVERIFIED", "no entries supplied")
    cps = {cp.tree_size: cp for cp in checkpoints}
    for cp in checkpoints:
        if cps[cp.tree_size].root_hash != cp.root_hash:
            all_mark("TAMPERED", "conflicting checkpoint roots at same size")
    proof_map = {(p.seq, p.tree_size): p for p in bundle.inclusion_proofs}
    if len(proof_map) != len(bundle.inclusion_proofs):
        all_mark("TAMPERED", "duplicate inclusion proof identity")
    for proof in bundle.inclusion_proofs:
        if proof.tree_size not in cps or proof.seq >= proof.tree_size:
            all_mark(
                "TAMPERED", "inclusion proof references an unknown checkpoint or invalid index"
            )
    for cp in checkpoints:
        complete = all(seq in parsed for seq in range(cp.tree_size))
        root_mismatch = False
        if complete:
            tree = MerkleTree([sealed_bytes(parsed[seq]) for seq in range(cp.tree_size)])
            root_mismatch = tree.root() != decode_hash(cp.root_hash)
        for seq, entry in parsed.items():
            if seq >= cp.tree_size:
                continue
            proof = proof_map.get((seq, cp.tree_size))
            if proof is None:
                mark(seq, "MISSING", "inclusion proof missing")
                if root_mismatch:
                    mark(
                        seq,
                        "TAMPERED",
                        "rebuilt root mismatch; missing proof prevents localization",
                    )
            elif not verify_inclusion(
                leaf_hash(sealed_bytes(entry)),
                seq,
                cp.tree_size,
                [decode_hash(h) for h in proof.proof],
                decode_hash(cp.root_hash),
            ):
                mark(seq, "TAMPERED", "inclusion proof failed")
    consistency = {(p.old_size, p.new_size): p for p in bundle.consistency_proofs}
    if len(consistency) != len(bundle.consistency_proofs):
        all_mark("TAMPERED", "duplicate consistency proof identity")
    ordered = sorted(cps.values(), key=lambda cp: cp.tree_size)
    for proof in bundle.consistency_proofs:
        old = cps.get(proof.old_size)
        new = cps.get(proof.new_size)
        if (
            old is None
            or new is None
            or not verify_consistency(
                proof.old_size,
                proof.new_size,
                decode_hash(old.root_hash),
                decode_hash(new.root_hash),
                [decode_hash(h) for h in proof.proof],
            )
        ):
            all_mark("TAMPERED", "consistency proof failed or references unknown checkpoint")
    for old, new in zip(ordered, ordered[1:]):
        if new.signer_timestamp < old.signer_timestamp:
            all_mark("TAMPERED", "checkpoint time decreases")
        if (old.tree_size, new.tree_size) not in consistency:
            all_mark("MISSING", "consistency proof missing")
    covered = max([cp.tree_size for cp in witnessed], default=0)
    for seq in parsed:
        if seq >= covered:
            mark(seq, "UNVERIFIED", "no witnessed checkpoint covers this sequence")
    for opening in bundle.openings:
        entry = parsed.get(opening.seq)
        try:
            value = entry.body.model_dump()
            for component in opening.field.split("."):
                value = value[component]
            valid = verify_opening(
                value, decode_base64url(opening.value), decode_base64url(opening.salt)
            )
        except (KeyError, ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            mark(opening.seq, "TAMPERED", "payload commitment opening failed")
    return VerificationReport(
        [results[seq] for seq in sorted(results)],
        [finding.model_dump() for finding in bundle.findings],
    )
