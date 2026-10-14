# Relay procedure (operator)

1. `python3 tests/live/harness.py` prints the next batch: `tests/live/relay/outbox/BATCH_<role>_r<N>.txt`.
2. Send that file's full text, unchanged, to the bot for `<role>`:
   writer = Test constitution Writer, agent = Test monitored Agent, judge = Test juge, tool = Test tool.
3. Save the bot's reply (one JSON object, verbatim) as `tests/live/relay/inbox/BATCH_<role>_r<N>.json`.
4. Run the harness again. Repeat until it prints `COMPLETE`.

Never send `cases.jsonl`, `make_cases.py`, `results.json`, `RESULTS.md`, or the logs to any bot.
Each pass rebuilds keys and ledger from scratch in `tests/live/state/` (git-ignored). Prompts are deterministic,
so an earlier reply is re-served only if its prompt hash still matches (a mismatch is logged as `stale_reply`).

Run 1 (2026-10-13) is archived in `run1/`. Run 2 starts from an empty `relay/`: every prompt changed, so no
run-1 reply is reused. Start a fresh conversation with each bot for run 2 so it does not carry run-1 context.
