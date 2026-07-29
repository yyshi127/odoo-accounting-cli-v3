"""Fail-closed runtime binding for approved Odoo report definitions.

The guard performs no file, network, SQL, or approval-signing work.  It accepts
only the immutable result of the external trust verifier plus one immutable
technical Odoo state captured by the trusted bootstrap.  When either input is
absent, report execution is unavailable rather than silently unguarded.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..domain.report_read import (
    NativeReportDefinitionBinding,
    ReportReadError,
)
from ..operations import canonical_json
from ..report_definition_baseline import (
    ReportDefinitionBaselineError,
    ReportDefinitionEntry,
    validate_observed_definition,
)
from ..report_definition_projection import (
    ROOT_BASELINE_IDENTITIES,
    ReportDefinitionProjectionError,
    validate_root_definition_projection,
)
from ..report_definition_trust import (
    ReportDefinitionTrustError,
    VerifiedReportDefinitionTrustEnvelope,
)
from .report_definition_observer import (
    ReportDefinitionObserverError,
    TechnicalDefinitionState,
    observe_report_definition_projections,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIXED_IDENTITIES = frozenset(ROOT_BASELINE_IDENTITIES)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ReportDefinitionObservation:
    """Immutable pre-execution evidence accepted only by its creating guard."""

    guard_token: object
    company_id: int
    report_family: str
    report_kind: str
    root_xmlid: str
    root_report_id: int
    entry_sha256: str
    trust_envelope_sha256: str
    pre_definition_json: bytes
    module_graph_sha256: str


@dataclass(frozen=True)
class OdooReportDefinitionGuard:
    """Compare one report's pre/post Odoo definition to one approved baseline."""

    env: Any
    database_uuid: str
    release_digest: str | None = None
    trust_envelope: VerifiedReportDefinitionTrustEnvelope | None = None
    technical_state: TechnicalDefinitionState | None = None
    now: Callable[[], datetime] = _utc_now
    observer: Callable[..., tuple[dict[str, object], ...]] = (
        observe_report_definition_projections
    )
    _guard_token: object = field(
        default_factory=object,
        init=False,
        repr=False,
        compare=False,
    )

    @staticmethod
    def _company_id(company: Any) -> int:
        company_id = getattr(company, "id", None)
        if (
            isinstance(company_id, bool)
            or not isinstance(company_id, int)
            or company_id <= 0
        ):
            raise ReportReadError("report definition company binding is invalid")
        return company_id

    @staticmethod
    def _canonical_database_uuid(value: object) -> str:
        if type(value) is not str:
            raise ReportReadError("report definition database binding is invalid")
        try:
            normalized = str(uuid.UUID(value))
        except ValueError as exc:
            raise ReportReadError(
                "report definition database binding is invalid"
            ) from exc
        if normalized != value:
            raise ReportReadError("report definition database binding is invalid")
        return value

    def _dependencies(
        self,
    ) -> tuple[
        VerifiedReportDefinitionTrustEnvelope,
        TechnicalDefinitionState,
        datetime,
    ]:
        if (
            type(self.trust_envelope)
            is not VerifiedReportDefinitionTrustEnvelope
            or type(self.technical_state) is not TechnicalDefinitionState
            or type(self.release_digest) is not str
            or _SHA256.fullmatch(self.release_digest) is None
            or not callable(self.now)
            or not callable(self.observer)
        ):
            raise ReportReadError(
                "approved report definition baseline is unavailable"
            )
        database_uuid = self._canonical_database_uuid(self.database_uuid)
        trust = self.trust_envelope
        technical_state = self.technical_state
        if (
            trust.runtime_binding.database_uuid != database_uuid
            or technical_state.database_uuid != database_uuid
            or not hmac.compare_digest(
                trust.runtime_binding.release_digest,
                self.release_digest,
            )
            or trust.catalog.production_promotion_allowed is not False
            or trust.verification.all_signatures_valid is not True
            or trust.verification.all_artifact_digests_valid is not True
            or trust.verification.no_key_or_approval_revoked is not True
            or trust.verification.production_promotion_allowed is not False
        ):
            raise ReportReadError(
                "approved report definition trust binding was rejected"
            )
        technical_state.module_graph
        current_time = self.now()
        if (
            not isinstance(current_time, datetime)
            or current_time.tzinfo is None
            or current_time.utcoffset() is None
        ):
            raise ReportReadError("report definition verification time is invalid")
        return trust, technical_state, current_time.astimezone(timezone.utc)

    @staticmethod
    def _identity(
        *,
        report_family: object,
        report_kind: object,
        root_xmlid: object,
    ) -> tuple[str, str, str]:
        identity = (report_family, report_kind, root_xmlid)
        if identity not in _FIXED_IDENTITIES:
            raise ReportReadError("report definition identity is not approved")
        return identity

    @staticmethod
    def _positive_record_id(value: object, field_name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ReportReadError(f"{field_name} is invalid")
        return value

    @staticmethod
    def _record_xmlid(
        technical_state: TechnicalDefinitionState,
        record_id: int,
    ) -> str:
        matches = tuple(
            binding.xmlid
            for binding in technical_state.external_ids
            if binding.model == "account.report"
            and binding.record_id == record_id
        )
        if len(matches) != 1:
            raise ReportReadError(
                "report definition record has no unique trusted XMLID"
            )
        return matches[0]

    def _observed_definition(
        self,
        *,
        technical_state: TechnicalDefinitionState,
        company_id: int,
        report_family: str,
        report_kind: str,
        root_xmlid: str,
    ) -> dict[str, object]:
        projections = self.observer(
            self.env,
            company_id=company_id,
            technical_state=technical_state,
        )
        if type(projections) is not tuple or len(projections) != len(
            _FIXED_IDENTITIES
        ):
            raise ReportReadError(
                "report definition observation is incomplete"
            )
        identities = tuple(
            (
                projection.get("baseline_identity", {}).get("family"),
                projection.get("baseline_identity", {}).get("kind"),
                projection.get("baseline_identity", {}).get("root_xmlid"),
            )
            if isinstance(projection, dict)
            and isinstance(projection.get("baseline_identity"), dict)
            else (None, None, None)
            for projection in projections
        )
        if (
            frozenset(identities) != _FIXED_IDENTITIES
            or len(set(identities)) != len(identities)
        ):
            raise ReportReadError(
                "report definition observation identities are incomplete"
            )
        matches = tuple(
            projection
            for identity, projection in zip(
                identities, projections, strict=True
            )
            if identity == (report_family, report_kind, root_xmlid)
        )
        if len(matches) != 1:
            raise ReportReadError(
                "report definition observation did not select one root"
            )
        projection = matches[0]
        validate_root_definition_projection(projection)
        baseline_identity = projection["baseline_identity"]
        if (
            baseline_identity["database_uuid"] != self.database_uuid
            or baseline_identity["company_id"] != company_id
        ):
            raise ReportReadError(
                "report definition observation binding differs"
            )
        return projection

    @staticmethod
    def _assert_report_records(
        *,
        entry: ReportDefinitionEntry,
        technical_state: TechnicalDefinitionState,
        root_xmlid: str,
        root_report_id: int,
        resolved_report_id: int | None = None,
    ) -> None:
        if (
            OdooReportDefinitionGuard._record_xmlid(
                technical_state, root_report_id
            )
            != root_xmlid
        ):
            raise ReportReadError(
                "report definition root record binding differs"
            )
        if resolved_report_id is None:
            return
        resolved_xmlid = OdooReportDefinitionGuard._record_xmlid(
            technical_state, resolved_report_id
        )
        definition = entry.definition
        reports = definition.get("reports")
        allowed_xmlids = (
            frozenset(
                report.get("xmlid")
                for report in reports
                if isinstance(report, dict)
            )
            if isinstance(reports, list)
            else frozenset()
        )
        if resolved_xmlid not in allowed_xmlids:
            raise ReportReadError(
                "resolved report is outside the approved definition closure"
            )

    def verify_pre(
        self,
        *,
        company: Any,
        report_family: str,
        report_kind: str,
        root_xmlid: str,
        root_report_id: int,
    ) -> ReportDefinitionObservation:
        """Capture and validate the complete approved definition before execution."""

        try:
            trust, technical_state, current_time = self._dependencies()
            company_id = self._company_id(company)
            family, kind, fixed_root_xmlid = self._identity(
                report_family=report_family,
                report_kind=report_kind,
                root_xmlid=root_xmlid,
            )
            record_id = self._positive_record_id(
                root_report_id, "report definition root record id"
            )
            entry = trust.select_entry(
                company_id=company_id,
                family=family,
                kind=kind,
                root_xmlid=fixed_root_xmlid,
                now=current_time,
            )
            self._assert_report_records(
                entry=entry,
                technical_state=technical_state,
                root_xmlid=fixed_root_xmlid,
                root_report_id=record_id,
            )
            observed_pre = self._observed_definition(
                technical_state=technical_state,
                company_id=company_id,
                report_family=family,
                report_kind=kind,
                root_xmlid=fixed_root_xmlid,
            )
            validate_observed_definition(
                entry,
                observed_pre=observed_pre,
                observed_post=observed_pre,
                now=current_time,
            )
            module_graph = observed_pre["module_graph"]
            if not isinstance(module_graph, dict):
                raise ReportReadError(
                    "report definition module graph is invalid"
                )
            module_graph_sha256 = hashlib.sha256(
                canonical_json(module_graph)
            ).hexdigest()
            return ReportDefinitionObservation(
                guard_token=self._guard_token,
                company_id=company_id,
                report_family=family,
                report_kind=kind,
                root_xmlid=fixed_root_xmlid,
                root_report_id=record_id,
                entry_sha256=entry.entry_sha256,
                trust_envelope_sha256=trust.envelope_sha256,
                pre_definition_json=canonical_json(observed_pre),
                module_graph_sha256=module_graph_sha256,
            )
        except ReportReadError:
            raise
        except (
            ReportDefinitionBaselineError,
            ReportDefinitionObserverError,
            ReportDefinitionProjectionError,
            ReportDefinitionTrustError,
        ) as exc:
            raise ReportReadError(
                "approved report definition precheck failed"
            ) from exc

    def verify_post(
        self,
        observation: Any,
        *,
        company: Any,
        report_family: str,
        report_kind: str,
        root_xmlid: str,
        root_report_id: int,
        resolved_report_id: int,
    ) -> NativeReportDefinitionBinding:
        """Reobserve and bind the result only when the same definition survived."""

        try:
            if (
                type(observation) is not ReportDefinitionObservation
                or observation.guard_token is not self._guard_token
            ):
                raise ReportReadError(
                    "report definition precheck evidence is invalid"
                )
            trust, technical_state, current_time = self._dependencies()
            company_id = self._company_id(company)
            family, kind, fixed_root_xmlid = self._identity(
                report_family=report_family,
                report_kind=report_kind,
                root_xmlid=root_xmlid,
            )
            record_id = self._positive_record_id(
                root_report_id, "report definition root record id"
            )
            resolved_id = self._positive_record_id(
                resolved_report_id, "resolved report definition record id"
            )
            if (
                observation.company_id != company_id
                or observation.report_family != family
                or observation.report_kind != kind
                or observation.root_xmlid != fixed_root_xmlid
                or observation.root_report_id != record_id
                or observation.trust_envelope_sha256
                != trust.envelope_sha256
            ):
                raise ReportReadError(
                    "report definition pre/post binding differs"
                )
            entry = trust.select_entry(
                company_id=company_id,
                family=family,
                kind=kind,
                root_xmlid=fixed_root_xmlid,
                now=current_time,
            )
            if observation.entry_sha256 != entry.entry_sha256:
                raise ReportReadError(
                    "approved report definition baseline changed"
                )
            self._assert_report_records(
                entry=entry,
                technical_state=technical_state,
                root_xmlid=fixed_root_xmlid,
                root_report_id=record_id,
                resolved_report_id=resolved_id,
            )
            observed_post = self._observed_definition(
                technical_state=technical_state,
                company_id=company_id,
                report_family=family,
                report_kind=kind,
                root_xmlid=fixed_root_xmlid,
            )
            module_graph = observed_post["module_graph"]
            if (
                not isinstance(module_graph, dict)
                or hashlib.sha256(canonical_json(module_graph)).hexdigest()
                != observation.module_graph_sha256
            ):
                raise ReportReadError(
                    "report definition module graph changed during execution"
                )
            post_definition_json = canonical_json(observed_post)
            if not hmac.compare_digest(
                observation.pre_definition_json,
                post_definition_json,
            ):
                raise ReportReadError(
                    "report definition changed during execution"
                )
            binding_sha256 = validate_observed_definition(
                entry,
                observed_pre=observation.pre_definition_json,
                observed_post=post_definition_json,
                now=current_time,
            )
            return NativeReportDefinitionBinding(
                schema_version=1,
                definition_sha256=entry.definition_sha256,
                baseline_catalog_sha256=entry.catalog_sha256,
                baseline_entry_sha256=entry.entry_sha256,
                source_candidate_sha256=entry.candidate_artifact_sha256,
                approval_set_sha256=entry.approval_set_sha256,
                allowed_signers_sha256=entry.allowed_signers.sha256,
                revocations_sha256=entry.revocations.sha256,
                oracle_contract_sha256=entry.oracle_contract.sha256,
                trust_envelope_sha256=trust.envelope_sha256,
                binding_sha256=binding_sha256,
                approvals_verified=True,
                revocations_checked=True,
                artifact_digests_verified=True,
                pre_matches_approved=True,
                post_matches_approved=True,
                same_transaction_snapshot_definition_equal=True,
            )
        except ReportReadError:
            raise
        except (
            ReportDefinitionBaselineError,
            ReportDefinitionObserverError,
            ReportDefinitionProjectionError,
            ReportDefinitionTrustError,
        ) as exc:
            raise ReportReadError(
                "approved report definition postcheck failed"
            ) from exc


__all__ = [
    "OdooReportDefinitionGuard",
    "ReportDefinitionObservation",
]
