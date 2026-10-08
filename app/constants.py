PREDICATES = (
    "offer_status", "offered_role", "start_date", "work_location", "org_unit",
    "manager_or_sponsor", "verified_channel", "identity_assurance_state",
    "preboarding_dependency_status", "preferred_name", "communication_language",
)
AUTHORITATIVE = frozenset(PREDICATES[:9])
SELF_DECLARED = frozenset(PREDICATES[9:])
ALLOWED_PURPOSES = {
    # F01 §1.4: preboarding_support is used by the operator and by F03. The F03 projection
    # service identity reads accepted state under this purpose (projection_service role).
    "preboarding_support": ("read", {"support", "projection_service"}),
    "candidate_self_view": ("read", {"candidate"}),
    "source_sync": ("mutation", {"source_service"}),
    "audit_reconstruction": ("read", {"auditor"}),
}
DENIED_PURPOSES = {
    "recruitment_evaluation", "performance_evaluation", "workforce_monitoring",
    "marketing", "model_training_cross_customer",
}
UNKNOWN_REASONS = {"no_claim", "expired", "not_yet_valid", "contested", "source_missing"}

