# Real ScribeJava date-gated JAR exercise

This folder contains two **actual JARs**: the legitimate
`com.github.scribejava:scribejava-core:8.3.3` and the malicious
`io.github.leetcrunch:scribejava-core:8.3.5`. The second is described in the
[Socket investigation](https://socket.dev/blog/malicious-maven-package-exfiltrates-oauth-credentials)
and the [OpenSSF advisory](https://github.com/ossf/malicious-packages/blob/main/osv/malicious/maven/io.github.leetcrunch:scribejava-core/MAL-2025-2552.json).

SHA-256 of the JARs:

- `8.3.3`: `b21eacc12983b0de585b05ef307b35f012e48f2898a4acdba529bbb0d379c443`
- `8.3.5`: `dbf92d66441f795dae60182002248bf167779dd1e856b4daf62e9eeded307c17`

Run `python demo_pkgs/scribejava/run_demo.py`. It compiles a trusted Java
exercise against the JAR, then loads that original JAR inside Bubblewrap at
four virtual dates around the 15th. The exercise calls
`OAuth20Service.signRequest` with synthetic credentials. A trusted HttpClient
proxy records the prepared request and throws before it can be transmitted.
Bubblewrap also has its network namespace disabled. The report shows a
blocked, prepared request to `pastebin.com` only on the trigger date; it does
not claim exfiltration occurred or inspect other Java code paths.

Requirements beyond WakeTrace's usual Linux Bubblewrap setup: Java 17 or
newer at `/usr/bin/java`, `javac` capable of `--release 17`, and a C compiler.
The run uses 1024 MB virtual memory by default.
