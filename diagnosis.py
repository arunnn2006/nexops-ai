"""Deterministic, evidence-based diagnosis. No external AI. Facts come from stored evidence;
hypotheses are labelled, carry capped confidence ('low' or 'medium'), and cite supporting evidence."""

from app.models import Diagnosis, Evidence, Incident

LIMITATIONS = [
    "Deterministic rules only; no external AI model was used.",
    "Hypotheses are inferred from temporal correlation and stored events, which does not prove causation.",
    "Only data held by NexOps (samples, events, deployment records) was considered; absence of evidence is not evidence of absence.",
    "Confidence is capped at 'medium' because root cause cannot be confirmed from this data alone.",
]


def _hyp(statement: str, confidence: str, evidence_ids: list[int], missing: list[str]) -> dict:
    assert confidence in ("low", "medium")
    return {
        "type": "hypothesis",
        "statement": statement,
        "confidence": confidence,
        "supporting_evidence_ids": evidence_ids,
        "missing_evidence": missing,
    }


def _service_hypotheses(inc: Incident, ev: list[Evidence]) -> tuple[list[dict], list[str]]:
    hyps: list[dict] = []
    steps: list[str] = []
    found = [e for e in ev if e.kind == "deployment" and e.data.get("found")]
    logs = [e for e in ev if e.kind == "log"]
    metric = next((e for e in ev if e.kind == "metric"), None)
    for d in found[:1]:
        lead = d.data.get("lead_minutes", 0)
        conf = "medium" if d.data.get("status") == "failed" or lead <= 30 else "low"
        hyps.append(
            _hyp(
                f"Version {d.data.get('version')} (deployment status '{d.data.get('status')}') was recorded {lead} min "
                "before the first anomalous sample, so the release may have introduced a regression. "
                "This is temporal correlation only.",
                conf,
                [d.id],
                ["Diff of the release against the previous version", "Error logs from before the deployment"],
            )
        )
        steps.append("Compare the release with the previous version and review its change log.")
    if logs:
        msgs = sorted({str(e.data.get("message", ""))[:80] for e in logs})
        hyps.append(
            _hyp(
                f"{len(logs)} application error log(s) were recorded around onset (e.g. '{msgs[0]}'), "
                "which suggests the failure is visible inside the service itself.",
                "medium" if len(logs) >= 3 else "low",
                [e.id for e in logs],
                ["Full stack traces", "Whether the same errors occurred before onset"],
            )
        )
        steps.append("Read the full application logs around the onset time.")
    if not hyps:
        hyps.append(
            _hyp(
                "The collected evidence does not identify a cause. Possible but unevidenced candidates: resource "
                "exhaustion, a failing dependency, or infrastructure/network problems.",
                "low",
                [metric.id] if metric else [],
                ["Application logs for the onset window", "Dependency health", "CPU/memory utilisation"],
            )
        )
        steps.append("Collect logs, dependency health and resource metrics for the onset window.")
    svc = inc.service
    if svc and svc.is_demo and svc.recovery_allowed:
        if found:
            steps.append("Consider an approved 'rollback_last_deployment' recovery (simulated for demo services).")
        steps.append("Consider an approved 'restart_service' recovery (simulated for demo services).")
    elif svc:
        steps.append(f"{svc.name} is not an approved demo recovery target; remediation must be done outside NexOps.")
    return hyps, steps


def _brute_force(inc: Incident, ev: list[Evidence]) -> tuple[list[dict], list[str]]:
    summary = next((e for e in ev if e.data.get("count") is not None), None)
    ids = [summary.id] if summary else []
    d = summary.data if summary else {}
    hyps = [
        _hyp(
            f"{d.get('count', 'Several')} failed logins in a short window are consistent with automated password guessing.",
            "medium",
            ids,
            ["Whether the source IP is known/expected", "Authentication logs beyond the detection window"],
        )
    ]
    if d.get("success_after_failure"):
        hyps.append(
            _hyp(
                "A successful login from the same source followed the failures; the account may have been accessed with a "
                "guessed credential. This is not confirmed.",
                "medium",
                ids + [e.id for e in ev if e.data.get("event_type") == "login_success"],
                ["Confirmation from the account owner", "Post-login activity for the account"],
            )
        )
    if (
        len(d.get("distinct_accounts", [])) <= 1
        and d.get("count", 0) < 2 * d.get("threshold", 5)
        and not d.get("success_after_failure")
    ):
        hyps.append(
            _hyp("A legitimate user may be repeatedly mistyping a password.", "low", ids, ["Contact the account owner"])
        )
    steps = [
        "Verify with the account owner whether the attempts were theirs.",
        "If a success followed the failures, rotate the credential and review account activity.",
        "Blocking the source is a network-level control outside NexOps.",
    ]
    return hyps, steps


def _suspicious(inc: Incident, ev: list[Evidence]) -> tuple[list[dict], list[str]]:
    s = next((e for e in ev if e.data.get("distinct_paths") is not None), None)
    n = len(s.data["distinct_paths"]) if s else 0
    hyps = [
        _hyp(
            "Requests probing multiple sensitive paths are consistent with automated scanning for exposed admin or config files."
            if n >= 5
            else "A crawler or misconfigured client may be requesting restricted paths.",
            "medium" if n >= 5 else "low",
            [s.id] if s else [],
            ["Whether the source IP is known", "Whether any request returned 200"],
        )
    ]
    return hyps, [
        "Confirm none of the probed paths exist or are exposed.",
        "Review access logs for 2xx responses from the same source.",
    ]


def _privilege(inc: Incident, ev: list[Evidence]) -> tuple[list[dict], list[str]]:
    ids = [e.id for e in ev][:3]
    hyps = [
        _hyp(
            "The change may be an authorised administrative action (for example onboarding).",
            "low",
            ids,
            ["Out-of-band confirmation from the acting admin"],
        ),
        _hyp(
            "The change may be a privilege escalation by a compromised or misused account.",
            "low",
            ids,
            ["Authentication history of the acting account", "A change ticket or approval record"],
        ),
    ]
    return hyps, [
        "Confirm the change with the acting admin through a separate channel.",
        "If unexpected, revert the role and review the acting account's recent activity.",
    ]


def build_diagnosis(incident: Incident) -> Diagnosis:
    ev = list(incident.evidence)
    facts = [{"type": "fact", "text": e.summary, "evidence_id": e.id, "kind": e.kind} for e in ev]
    facts.insert(
        0,
        {
            "type": "fact",
            "text": f"Rule '{incident.rule}' triggered: {incident.summary}",
            "evidence_id": None,
            "kind": "rule",
        },
    )
    handlers = {
        "service_down": _service_hypotheses,
        "high_error_rate": _service_hypotheses,
        "high_latency": _service_hypotheses,
        "brute_force": _brute_force,
        "suspicious_access": _suspicious,
        "privilege_change": _privilege,
    }
    hyps, steps = handlers[incident.rule](incident, ev)
    return Diagnosis(
        incident_id=incident.id,
        method="deterministic",
        summary=f"{len(facts)} observed fact(s) and {len(hyps)} hypothesis(es). Hypotheses are not confirmed causes.",
        facts=facts,
        hypotheses=hyps,
        next_steps=steps,
        limitations=LIMITATIONS,
    )
