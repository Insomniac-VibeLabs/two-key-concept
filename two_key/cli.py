"""Command line for the concept build.

  two-key init-key DIR
  two-key sign-constitution --key KEY --prose FILE --rules FILE --out FILE
  two-key demo
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .constitution import load_unsigned, save_envelope, sign_constitution
from .keys import generate_private_key, load_private_key, save_private_key, save_public_key


def _init_key(args) -> int:
    key = generate_private_key()
    dest = Path(args.dir)
    save_private_key(dest / "principal.pem", key)
    save_public_key(dest / "principal.pub.pem", key.public_key())
    print(f"wrote {dest / 'principal.pem'}")
    return 0


def _sign(args) -> int:
    key = load_private_key(args.key)
    prose, rules = load_unsigned(args.prose, args.rules)
    save_envelope(args.out, sign_constitution(prose, rules, key))
    print(f"wrote {args.out}")
    return 0


def _demo(_args) -> int:
    import tempfile
    from .constitution import sign_constitution
    from .core import TwoKey
    from .gateway import ToolGateway
    from .ledger import Ledger
    from .quorum import QuorumPolicy
    from .testing import FixedJudge

    key = generate_private_key()
    prose = "Never wire money. Never spend more than 200 dollars. Drafts are allowed."
    rules = [
        {"id": "tools", "allow_only_tools": ["search", "email_draft"]},
        {"id": "no-wires", "deny_if": {"tool": "wire_transfer"}},
        {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
    ]
    envelope = sign_constitution(prose, rules, key)
    with tempfile.TemporaryDirectory() as tmp:
        ledger = Ledger(tmp, key)
        judges = [FixedJudge("a", "yes", provider="local-a"), FixedJudge("b", "yes", provider="local-b")]
        tk = TwoKey(ledger, key.public_key(), __import__("two_key.constitution", fromlist=["verify_signed"]).verify_signed(envelope, key.public_key()),
                    judges, private_key=key, quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True)
        denied = tk.authorize({"tool": "wire_transfer", "amount_usd": 10, "data_class": "public", "irreversible": True},
                              {}, "please wire the funds")
        allowed = tk.authorize({"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                               {"to": "ada@example"}, "draft a note")
        gateway = ToolGateway(ledger, tk.issuer, tk.compiled, tools={"email_draft": lambda a: {"drafted": a.get("to")}})
        redeemed = gateway.invoke(allowed.token, "email_draft", {"to": "ada@example"}) if allowed.token else None
        replay = gateway.invoke(allowed.token, "email_draft", {"to": "ada@example"}) if allowed.token else None
    print(json.dumps({
        "wire_denied": denied.reason,
        "draft_allowed": allowed.allowed,
        "redeemed": None if redeemed is None else redeemed.reason,
        "replay": None if replay is None else replay.reason,
    }, indent=2))
    return 0 if denied.allowed is False and allowed.allowed and redeemed and redeemed.allowed and replay and not replay.allowed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="two-key")
    sub = parser.add_subparsers(dest="cmd", required=True)
    init = sub.add_parser("init-key")
    init.add_argument("dir")
    init.set_defaults(func=_init_key)
    sign = sub.add_parser("sign-constitution")
    sign.add_argument("--key", required=True)
    sign.add_argument("--prose", required=True)
    sign.add_argument("--rules", required=True)
    sign.add_argument("--out", required=True)
    sign.set_defaults(func=_sign)
    demo = sub.add_parser("demo")
    demo.set_defaults(func=_demo)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
