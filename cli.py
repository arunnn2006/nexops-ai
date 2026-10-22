"""Command line helpers: create-user, seed-demo, detect.

Passwords are read from a hidden prompt or from NEXOPS_NEW_USER_PASSWORD; never from command-line arguments.
"""

import argparse
import getpass
import os
import sys

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import hash_password
from app.db.session import make_engine, make_session_factory
from app.models import User
from app.services.audit import record_audit
from app.services.detection import run_detection
from app.services.diagnosis import build_diagnosis
from app.services.seed import reset_demo_data, seed_demo


def _session():
    settings = get_settings()
    return settings, make_session_factory(make_engine(settings.database_url))()


def cmd_create_user(args) -> int:
    try:
        email = TypeAdapter(EmailStr).validate_python(args.email).lower()
    except ValidationError:
        print("Invalid email address", file=sys.stderr)
        return 2
    password = os.environ.get("NEXOPS_NEW_USER_PASSWORD")
    if not password:
        password = getpass.getpass("Password (min 12 chars): ")
        if password != getpass.getpass("Repeat password: "):
            print("Passwords do not match", file=sys.stderr)
            return 2
    if len(password) < 12:
        print("Password must be at least 12 characters", file=sys.stderr)
        return 2
    _, db = _session()
    with db:
        if db.scalar(select(User.id).where(User.email == email)):
            print("A user with that email already exists", file=sys.stderr)
            return 1
        user = User(email=email, password_hash=hash_password(password), role=args.role)
        db.add(user)
        db.flush()
        record_audit(
            db,
            actor=None,
            actor_email="cli",
            action="user.create_cli",
            target_type="user",
            target_id=user.id,
            detail={"email": email, "role": args.role},
        )
        db.commit()
    print(f"Created {args.role} user {email}")
    return 0


def cmd_seed(args) -> int:
    settings, db = _session()
    with db:
        from app.models import Service

        if db.scalar(select(Service.id).limit(1)):
            if not args.reset:
                print(
                    "Services already exist. Use --reset to replace sample data (users and audit log are kept).",
                    file=sys.stderr,
                )
                return 1
            reset_demo_data(db)
        counts = seed_demo(db)
        print("Seeded:", counts)
        if args.detect:
            created = run_detection(db, settings)
            for inc in created:
                db.add(build_diagnosis(inc))
            db.commit()
            print(f"Detection created {len(created)} incident(s)")
    return 0


def cmd_detect(_args) -> int:
    settings, db = _session()
    with db:
        created = run_detection(db, settings)
        for inc in created:
            db.add(build_diagnosis(inc))
        db.commit()
    print(f"Detection created {len(created)} incident(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    cu = sub.add_parser("create-user", help="create a user with a given role")
    cu.add_argument("--email", required=True)
    cu.add_argument("--role", choices=["viewer", "operator", "admin"], default="viewer")
    cu.set_defaults(fn=cmd_create_user)
    sd = sub.add_parser("seed-demo", help="load synthetic demo services, samples and events")
    sd.add_argument("--reset", action="store_true", help="replace existing sample data")
    sd.add_argument("--detect", action="store_true", help="run detection right after seeding")
    sd.set_defaults(fn=cmd_seed)
    dt = sub.add_parser("detect", help="run incident detection once")
    dt.set_defaults(fn=cmd_detect)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
