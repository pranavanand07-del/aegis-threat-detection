Try AEGIS without real logs (run from the project root, server started with the default command):
  curl -X POST "localhost:8080/aegis/api/ingest?type=web"      --data-binary @samples/aegis/access.log
  curl -X POST "localhost:8080/aegis/api/ingest?type=firewall" --data-binary @samples/aegis/firewall.log
  curl -X POST "localhost:8080/aegis/api/ingest?type=winxml"   --data-binary @samples/aegis/windows-events.xml
These are labelled API (not Observed). The log timestamps are fixed (2026-10-10), so use the time range
"Everything stored" or "Last 24 hours" on the dashboard to see them.
