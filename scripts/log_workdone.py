import sys, datetime, pathlib

msg = sys.argv[1] if len(sys.argv) > 1 else "work done"
ts = datetime.datetime.utcnow().isoformat()
path = pathlib.Path("WORKDONE.md")
path.write_text((path.read_text() if path.exists() else "# Work Log\n\n") + f"- {ts}Z — {msg}\n")
print(f"Appended: {msg}")
