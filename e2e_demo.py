"""Reproducible end-to-end walkthrough against a RUNNING backend. Exits non-zero on any failed step.

Prerequisites (see docs/DEMO.md): migrated DB, `python -m app.cli seed-demo --reset`, one admin and one operator
user created with `python -m app.cli create-user`. Credentials are read from the environment, never from argv:
  E2E_BASE_URL (default http://127.0.0.1:8000/api/v1)
  E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD / E2E_OPERATOR_EMAIL / E2E_OPERATOR_PASSWORD
"""
import os
import sys

import httpx

BASE = os.environ.get("E2E_BASE_URL", "http://127.0.0.1:8000/api/v1")
steps: list[tuple[str, bool]] = []


def check(name: str, ok: bool, extra: str = "") -> None:
    steps.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {extra}")
    if not ok:
        sys.exit(1)


def login(c: httpx.Client, email_var: str, pw_var: str) -> dict:
    email, pw = os.environ.get(email_var), os.environ.get(pw_var)
    if not email or not pw:
        sys.exit(f"Set {email_var} and {pw_var}")
    r = c.post(f"{BASE}/auth/login", json={"email": email, "password": pw})
    check(f"login {email}", r.status_code == 200, f"(role={r.json().get('user', {}).get('role')})")
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


with httpx.Client(timeout=30) as c:
    check("API ready", c.get(f"{BASE}/ready").status_code == 200)
    admin, op = login(c, "E2E_ADMIN_EMAIL", "E2E_ADMIN_PASSWORD"), login(c, "E2E_OPERATOR_EMAIL", "E2E_OPERATOR_PASSWORD")

    r = c.post(f"{BASE}/incidents/detect", headers=op)
    check("run detection", r.status_code == 200, f"(created {r.json()['created']} new)")
    page = c.get(f"{BASE}/incidents", headers=op, params={"limit": 100}).json()
    rules = {i["rule"] for i in page["items"]}
    check("all six rule types present", rules >= {"brute_force", "service_down", "high_error_rate", "high_latency",
                                                  "suspicious_access", "privilege_change"}, f"({sorted(rules)})")

    outage = next(i for i in page["items"] if i["rule"] == "service_down" and i["status"] != "resolved")
    detail = c.get(f"{BASE}/incidents/{outage['id']}", headers=op).json()
    check("outage has evidence + diagnosis", bool(detail["evidence"]) and detail["latest_diagnosis"] is not None)
    check("hypotheses are labelled and confidence capped",
          all(h["type"] == "hypothesis" and h["confidence"] in ("low", "medium") for h in detail["latest_diagnosis"]["hypotheses"]))

    svc_id, name = outage["service_id"], outage["service_name"]
    r = c.post(f"{BASE}/recovery/requests", headers=op, json={"service_id": svc_id, "action": "restart_service",
                                                              "incident_id": outage["id"], "reason": "e2e demo"})
    check("operator requests simulated restart", r.status_code == 201, f"(status={r.json().get('status')})")
    rid = r.json()["id"]
    r = c.post(f"{BASE}/recovery/requests/{rid}/execute", headers=op,
               json={"confirm": True, "confirmation_phrase": f"restart_service {name}"})
    check("execution BLOCKED before approval", r.status_code == 409)
    r = c.post(f"{BASE}/recovery/requests", headers=op, json={"service_id": svc_id, "action": "rm -rf /"})
    check("non-allowlisted action rejected", r.status_code == 422)
    r = c.post(f"{BASE}/recovery/requests/{rid}/approve", headers=admin, json={"note": "e2e"})
    check("admin approves", r.status_code == 200 and r.json()["status"] == "approved")
    r = c.post(f"{BASE}/recovery/requests/{rid}/execute", headers=op, json={"confirm": True, "confirmation_phrase": "yes"})
    check("execution BLOCKED with wrong confirmation phrase", r.status_code == 422)
    r = c.post(f"{BASE}/recovery/requests/{rid}/execute", headers=op,
               json={"confirm": True, "confirmation_phrase": f"restart_service {name}"})
    body = r.json()
    check("simulated execution + verification", r.status_code == 200 and body["status"] == "executed"
          and body["verification"]["passed"] is True, f"(mode={body['mode']}, simulated={body['result']['simulated']})")
    check("service now healthy", c.get(f"{BASE}/services/{svc_id}", headers=op).json()["status"] == "healthy")
    audit = c.get(f"{BASE}/audit", headers=admin, params={"action": "recovery", "limit": 50}).json()
    actions = {a["action"] for a in audit}
    check("audit trail covers request/approve/execute", {"recovery.request", "recovery.approve", "recovery.execute"} <= actions)
    check("denied attempts are audited", any(a["outcome"] == "denied" for a in audit))

print(f"\nAll {len(steps)} end-to-end steps passed.")
