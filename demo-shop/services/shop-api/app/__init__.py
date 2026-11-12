"""shop-api: the demo-shop's application (task B9). INTENTIONALLY VULNERABLE: a benchmark target for SentinelCI.

Do not deploy it, do not expose it beyond localhost, do not reuse any of this code. Every seeded weakness is
listed in demo-shop/ground-truth/findings.yaml and names its id where it is (GT-SAST-*, GT-CANARY-*). The
release image (Dockerfile.release) runs it as UID 10001 on port 8080, writing only to /tmp.
"""
