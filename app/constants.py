PREDICATES = (
    "offer_status", "offered_role", "start_date", "work_location", "org_unit",
    "manager_or_sponsor", "verified_channel", "identity_assurance_state",
    "preboarding_dependency_status", "preferred_name", "communication_language",
)
AUTHORITATIVE = frozenset(PREDICATES[:9])
SELF_DECLARED = frozenset(PREDICATES[9:])
ALLOWED_PURPOSES = {
    "preboarding_support": ("read", {"support"}),
    "candidate_self_view": ("read", {"candidate"}),
    "source_sync": ("mutation", {"source_service"}),
    "audit_reconstruction": ("read", {"auditor"}),
}
DENIED_PURPOSES = {
    "recruitment_evaluation", "performance_evaluation", "workforce_monitoring",
    "marketing", "model_training_cross_customer",
}
UNKNOWN_REASONS = {"no_claim", "expired", "contested", "source_missing"}

