"""Command line for the concept build.

  two-key init-key DIR
  two-key sign-constitution --key KEY --prose FILE --rules FILE --out FILE
  two-key authorize --key KEY --ledger DIR --constitution FILE --judges FILE --tool NAME
                    [--agent-session-env NAME] [--ttl-seconds N] [--emit-token PATH]
  two-key demo

``authorize`` never prints the bearer token. It prints the decision with the token's
jti and digest (the ledger's ``capability_issued.token_hash``). ``--emit-token PATH``
writes the token itself to a new file with mode 0600. The agent session secret is
read from the environment variable named by ``--agent-session-env``; it is never
taken on argv, where other local users and shell history can see it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .constitution import load_unsigned, save_envelope, sign_constitution
from .keys import generate_private_key, load_private_key_file, save_private_key, save_public_key


def _init_key(args) -> int:
    key = generate_private_key()
    dest = Path(args.dir)
    try:
        save_private_key(dest / "principal.pem", key)
    except FileExistsError:
        print(f"refusing to overwrite {dest / 'principal.pem'}", file=sys.stderr)
        return 1
    save_public_key(dest / "principal.pub.pem", key.public_key())
    print(f"wrote {dest / 'principal.pem'}")
    return 0


def _sign(args) -> int:
    key = load_private_key_file(args.key)
    prose, rules, specs = load_unsigned(args.prose, args.rules)
    save_envelope(args.out, sign_constitution(prose, rules, key, specs))
    print(f"wrote {args.out}")
    return 0


def _demo(_args) -> int:
    import tempfile
    from .constitution import sign_constitution
    from .core import TwoKey
    from .gateway import ToolGateway
    from .ledger import Ledger
    from .quorum import QuorumPolicy
    from .testing import TEST_AGENT, FixedJudge

    key = generate_private_key()
    prose = "Never wire money. Never spend more than 200 dollars. Drafts are allowed."
    rules = [
        {"id": "tools", "allow_only_tools": ["search", "email_draft"]},
        {"id": "no-wires", "deny_if": {"tool": "wire_transfer"}},
        {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
    ]
    specs = {
        "search": {"irreversible": False, "data_class_floor": "public"},
        "email_draft": {"irreversible": False, "data_class_floor": "public",
                        "counterparties": [{"json_path": "to", "allow": ["ada@example"]}]},
    }
    envelope = sign_constitution(prose, rules, key, specs)
    with tempfile.TemporaryDirectory() as tmp:
        ledger = Ledger(tmp, key)
        judges = [FixedJudge("a", "yes", provider="local-a", vendor="local", local_weights=True),
                  FixedJudge("b", "yes", provider="cloud-b", vendor="other")]
        tk = TwoKey(ledger, key.public_key(), __import__("two_key.constitution", fromlist=["verify_signed"]).verify_signed(envelope, key.public_key()),
                    judges, private_key=key, quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True, monitored_agent=TEST_AGENT)
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



def _write_token(path: Path, token: str) -> None:
    """Write the bearer token to a new file, mode 0600 from creation. Never overwrite."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(token + "\n")


def _authorize(args) -> int:
    from .constitution import load_envelope
    from .core import TwoKey
    from .identity import load_monitored_agent_file
    from .judges.config import load_config_file
    from .ledger import Ledger
    if args.agent_session is not None:
        print("--agent-session took the secret on the command line and is no longer accepted; "
              "put it in an environment variable and pass --agent-session-env NAME", file=sys.stderr)
        return 1
    agent_session = None
    if args.agent_session_env:
        agent_session = os.environ.get(args.agent_session_env)
        if not agent_session:
            print(f"environment variable {args.agent_session_env} is not set", file=sys.stderr)
            return 1
    token_path = Path(args.emit_token) if args.emit_token else None
    if token_path is not None and (token_path.exists() or token_path.is_symlink()):
        print(f"refusing to overwrite {token_path}", file=sys.stderr)
        return 1
    key = load_private_key_file(args.key)
    judges, policy = load_config_file(Path(args.judges))
    # The monitored agent is declared by the operator in the judges file, never by the agent.
    agent = load_monitored_agent_file(Path(args.judges))
    ledger = Ledger(args.ledger, key)
    tk = TwoKey.load(ledger, key.public_key(), load_envelope(args.constitution), judges,
                     private_key=key, quorum=policy, monitored_agent=agent,
                     ttl_seconds=args.ttl_seconds)
    arguments = json.loads(args.args)
    if not isinstance(arguments, dict):
        raise SystemExit("args must be a JSON object")
    action = {"tool": args.tool, "amount_usd": args.amount_usd, "data_class": args.data_class,
              "irreversible": args.irreversible}
    if args.counterparty:
        action["counterparty"] = args.counterparty
    decision = tk.authorize(action, arguments, args.proposal, agent_session=agent_session, origin="cli")
    record = decision.to_record()
    if decision.allowed and token_path is not None:
        try:
            _write_token(token_path, decision.token)
        except OSError as e:
            print(f"could not write {token_path}: {e.strerror}", file=sys.stderr)
            print(json.dumps(record, indent=2))
            return 1
        record["token_file"] = str(token_path)
    print(json.dumps(record, indent=2))
    return 0 if decision.allowed else 2


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
    auth = sub.add_parser("authorize", help="run Path A and Path B; do not execute the tool")
    auth.add_argument("--key", required=True)
    auth.add_argument("--ledger", required=True)
    auth.add_argument("--constitution", required=True)
    auth.add_argument("--judges", required=True)
    auth.add_argument("--tool", required=True)
    auth.add_argument("--args", default="{}")
    auth.add_argument("--proposal", required=True)
    auth.add_argument("--amount-usd", type=float, default=0.0)
    auth.add_argument("--data-class", default="classified",
                      help="defaults to classified, matching normalize_action")
    auth.add_argument("--irreversible", action=argparse.BooleanOptionalAction, default=True,
                      help="defaults to true; pass --no-irreversible for a reversible call")
    auth.add_argument("--counterparty", default="")
    auth.add_argument("--agent-session-env", default=None, metavar="NAME",
                      help="name of the environment variable holding the agent session secret")
    auth.add_argument("--agent-session", default=None, help=argparse.SUPPRESS)
    auth.add_argument("--ttl-seconds", type=int, default=120,
                      help="token lifetime; the gateway refuses longer tokens (default 120)")
    auth.add_argument("--emit-token", default=None, metavar="PATH",
                      help="write the token to a new 0600 file; it is never printed")
    auth.set_defaults(func=_authorize)
    demo = sub.add_parser("demo")
    demo.set_defaults(func=_demo)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
