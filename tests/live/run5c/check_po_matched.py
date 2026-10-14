"""Standalone local check (Cyber sign-off, run 5b): po_matched default:true is safe for pay_vendor.

Uses only documented APIs: `python -m two_key init-key` / `sign-constitution` (HOWTO "Create a principal key
and sign a constitution"), TwoKey.load / authorize (HOWTO "Authorize from Python"), decision.path_a /
decision.reason (same section), derive_failed:field_missing:<field> (HOWTO "Custom Path A fields").
The run5 field registry and tool_specs are read verbatim from harness.py (TOOL_SPECS_YAML) without executing it.
Judges are loopback endpoints on a closed port, so Path B abstains/denies; this check asserts Path A only.
No bot is contacted; nothing outside a temp dir is written.
"""
import ast, os, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
src = (HERE / "harness.py").read_text()
SPECS = next(n.value.value for n in ast.parse(src).body if isinstance(n, ast.Assign)
             and any(getattr(t, "id", None) == "TOOL_SPECS_YAML" for t in n.targets))

RULES = """hard_rules:
  - id: tools
    allow_only_tools: [pay_vendor, send_message, book_appointment, lookup]
  - id: no-classified
    deny_if: {data_class_in: [classified]}
  - id: po-mismatch
    deny_if_fields: {po_matched: {eq: false}}
""" + SPECS

def cli(*a):
    r = subprocess.run([sys.executable, "-m", "two_key", *a], cwd=REPO, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"cli {a[0]} failed: {r.stderr}")

def main():
    from two_key.constitution import load_envelope
    from two_key.core import TwoKey
    from two_key.identity import load_monitored_agent_file
    from two_key.judges.config import load_config_file
    from two_key.keys import load_private_key_file
    from two_key.ledger import Ledger

    d = Path(tempfile.mkdtemp(prefix="po_check_")); os.chmod(d, 0o700)
    (d / "rules.yaml").write_text(RULES)
    (d / "prose.md").write_text("Pay only invoices that match their purchase order.\n")
    cli("init-key", str(d / "keys"))
    cli("sign-constitution", "--key", str(d / "keys/principal.pem"), "--prose", str(d / "prose.md"),
        "--rules", str(d / "rules.yaml"), "--out", str(d / "c.json"))
    os.environ.update(POCHK_AGENT="agent-po-check-1", POCHK_JA="judgea-po-check-2", POCHK_JB="judgeb-po-check-3")
    (d / "judges.yaml").write_text("""monitored_agent:
  id: agent
  model: agent
  provider: local
  base_url: http://127.0.0.1:9/v1
  credential_env: POCHK_AGENT
judges:
  - {id: ja, type: openai_compatible, provider: local, model: ja, base_url: "http://127.0.0.1:9/v1", auth: {type: env, var: POCHK_JA}, timeout: 2}
  - {id: jb, type: openai_compatible, provider: local, model: jb, base_url: "http://127.0.0.1:9/v1", auth: {type: env, var: POCHK_JB}, timeout: 2}
quorum:
  timeout_seconds: 5
""")
    key = load_private_key_file(str(d / "keys/principal.pem"))
    judges, policy = load_config_file(d / "judges.yaml")
    tk = TwoKey.load(Ledger(str(d / "ledger"), key), key.public_key(), load_envelope(str(d / "c.json")), judges,
                     private_key=key, quorum=policy, monitored_agent=load_monitored_agent_file(d / "judges.yaml"))
    base = {"payee": "alpine-medsupply.example", "amount": 412.5, "currency": "USD",
            "invoice": "AMS-30871", "memo": "Exam gloves, Oct"}
    claim = {"tool": "pay_vendor", "data_class": "financial", "irreversible": True}
    ok = True
    def run(name, args, want_reason, want_path_a_allowed):
        nonlocal ok
        dec = tk.authorize(dict(claim), args, "pay Alpine invoice AMS-30871", agent_session=os.environ["POCHK_AGENT"])
        pa = dec.path_a or {}
        good = (not dec.allowed) if want_path_a_allowed is False else True
        if want_reason: good = good and want_reason in (str(dec.reason) + " " + str(pa.get("reason")))
        if want_path_a_allowed is not None: good = good and bool(pa.get("allowed")) == want_path_a_allowed
        print(f"{'PASS' if good else 'FAIL'} {name}: allowed={dec.allowed} reason={dec.reason!r} path_a={pa.get('allowed')}/{pa.get('reason')!r}")
        ok &= good
    run("po_matched=false denied", {**base, "po_matched": False}, "po-mismatch", False)
    run("po_matched missing -> field_missing", dict(base), "derive_failed:field_missing:po_matched", False)
    run("control po_matched=true passes Path A", {**base, "po_matched": True}, None, True)
    print("ALL OK" if ok else "CHECK FAILED"); sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
