---
category: finding
key: pcap-tshark-255-investigation
updated: 2026-09-06T08:03:45.582Z
scope: local
---
# PcapFileExtractStreams test_main TSharkCrashException (retcode 255) investigation

## Symptom
CI: test_main fails. Chain: tshark exits 255 on 2.pcap (0 packets) -> pyshark TSharkCrashException -> script ValueError (line 277) -> main return_error (line 379) -> sys.exit(0) -> pytest SystemExit. Trailing PytestUnraisableExceptionWarning: same crash again in Capture.__del__ during GC.

## Facts established by running the real image (demisto/pcap-miner:1.0.0.10133006)
- Image: Alpine 3.24.1, Python 3.12.13, pyshark 0.6, TShark 4.6.6 (Copyright 1998-2026), tshark binary mtime 2026-05-24, image Created 2026-06-14, digest sha256:2b9fa576...ca6c27a2.
- Fixtures unchanged since Feb 2024; 2.pcap is a valid big-endian pcap; tshark -r 2.pcap => exit 0, parses fine.
- Reproduction attempts that ALL PASSED (0 failures) in current image:
  - exact script args, sequential over 1/2/3.pcap, with sys.stderr=/dev/null swap
  - preset asyncio loop
  - 90x hammer loop
  - forced async close via loop.run_until_complete(cap.close_async())
  - broken HOME=/nonexistent-ro
- Reproduction that PARTIALLY matched: closing the event loop before cap GC reproduces the __del__ -> close() -> run_until_complete -> "RuntimeError: Event loop is closed" cascade == the trailing PytestUnraisableExceptionWarning stack. But it yields RuntimeError, NOT the retcode-255 TSharkCrashException of the primary failure.

## Confound
All local runs are under QEMU emulation (amd64 image on arm64 host) - timing skew. CI runs amd64 natively. Could mask/alter an async subprocess race.

## Conclusions (evidence-bounded)
- PROVEN: failure is environmental, not in parsing logic. Same inputs + current image = no crash.
- PROVEN mechanism class: pyshark cleanup runs run_until_complete against a torn-down/mismatched event loop (pytest-asyncio STRICT context) -> unraisable exceptions in __del__.
- NOT PROVEN by me: (a) that the tag digest changed between CI run and now (need CI-pulled digest to compare vs 2b9fa576); (b) the exact trigger of retcode 255 specifically.

## Design issues found
1. test_main is not a unit test - runs live tshark via pyshark.FileCapture; only demisto surface mocked. Fragile to image/tshark/pyshark/python drift.
2. Script mutes tshark stderr: sys.stderr = devnull at PcapFileExtractStreams.py:265 -> that is why CI log shows "Last error line: None".

## Recommended fix
- Durable: mock pyshark.FileCapture in test_main -> deterministic, env-independent.
- Hardening: stop swallowing stderr (line 265), log via demisto.debug; pin pcap-miner by digest.
- To CONFIRM rebuild: compare CI-pulled Digest sha256 vs current 2b9fa576...ca6c27a2; or docker buildx imagetools inspect the tag.