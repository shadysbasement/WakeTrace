# Monthly time bomb: incident-based WakeTrace check

Socket documented a malicious ScribeJava Maven package (`io.github.leetcrunch:scribejava-core:8.3.5`) that checked whether the day of the month was the 15th before attempting to exfiltrate OAuth credentials. The original artifact is Java. WakeTrace runs Python targets, so `candidate.py` is an explicit Python adaptation of the date gate and credential/network sequence, not a copy of the original package. It uses only WakeTrace-injected fake credentials and the reserved `example.invalid` destination inside WakeTrace's network-isolated sandbox.

Source: https://socket.dev/blog/malicious-maven-package-exfiltrates-oauth-credentials

Run from the WakeTrace repository:

```bash
.venv/bin/python examples/incident_monthly/run_demo.py --output /tmp/waketrace-incident-monthly
.venv/bin/waketrace terminal --report /tmp/waketrace-incident-monthly/report.json --lock /tmp/waketrace-incident-monthly/behavior.lock.json
```

The runner chooses tested horizons around the next 15th at noon UTC. The prior day should have no new risk; the 15th should show synthetic credential reads and a blocked network attempt. The generated report is local to the selected output folder.
