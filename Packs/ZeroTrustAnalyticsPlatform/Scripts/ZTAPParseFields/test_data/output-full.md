### ## (*) xdr 0 (2021-06-17T14:02:06Z)

|Key|Value|Order|
|---|---|---|
| Name (name) | CS19 - Unsigned process spawning svchost.exe | 0 |
| Process Name (actor_process_image_name) | svchost.exe | 1 |
| Command Line (actor_process_command_line) | C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc | 2 |
| Host Name (host_name) | prod01 | 3 |
| User Name (user_name) | NT AUTHORITY\SYSTEM | 4 |
| Path (actor_process_image_path) | C:\Windows\System32\svchost.exe | 5 |
| Process Sha256 (actor_process_image_sha256) | ec24b848f97a5d5614e859859aa29883bf21e0a11a6df8d324576f31e6bc8c57 | 6 |
| Actor Process Image Md5 (actor_process_image_md5) | d3f10c16dd794987b1395823fbffeeb9 | 7 |
| Signature Status (actor_process_signature_status) | Signed | 8 |
| Signature Vendor (actor_process_signature_vendor) | Microsoft Corporation | 9 |
| Causality Actor Process Image Name (causality_actor_process_image_name) | ClassicStartMenu.exe | 10 |
| Causality Actor Process Command Line (causality_actor_process_command_line) | "C:\Program Files\Classic Shell\ClassicStartMenu.exe" -autorun | 11 |
| Causality Actor Process Image Path (causality_actor_process_image_path) | C:\Program Files\Classic Shell\ClassicStartMenu.exe | 12 |
| Causality Actor Process Signature Status (causality_actor_process_signature_status) | Invalid Signature | 13 |
| Causality Actor Process Signature Vendor (causality_actor_process_signature_vendor) | Ivaylo Beltchev | 14 |
| Event Timestamp (event_timestamp) | 2021-06-17T14:02:06.417426Z | 15 |
| XDR Severity (xdr_severity) | medium | 16 |
| Alert_Description (description) | Process action type = execution Process cgo signature = Unsigned, Invalid Signature AND initiated by = svchost.exe Host host os != linux | 17 |
| Action (action) | DETECTED | 18 |
| Action Country (action_country) | UNKNOWN | 19 |
| Action Process Causality ID (action_process_causality_id) | MTfDceuFh1j5S0AXBcWkng== | 20 |
| Child Process Name (action_process_image_name) | CompatTelRunner.exe | 21 |
| Child Process Sha256 (action_process_image_sha256) | e8f88ffee8ca76dbfc5da78a7c2a1f8a826e5d1d9f21415dc7147b47e62768d5 | 22 |
| Action Process Instance Id (action_process_instance_id) | AdchegZ034MAADNwAAAAAA== | 23 |
| Action Process Signature Status (action_process_signature_status) | Signed | 24 |
| Child Process Signature Vendor (action_process_signature_vendor) | Microsoft Corporation | 25 |
| Actor Causality ID (actor_causality_id) | EFIE8+iVL8ouYFBxFINyhg== | 26 |
| Process Instance ID (actor_process_instance_id) | EFIE8+iVL8ouYFBxFINyhg== | 27 |
| Agent OS Type (agent_os_type) | Windows | 28 |
| Case ID (case_id) | 7331 | 29 |
| Causality Actor Process Image Sha256 (causality_actor_process_image_sha256) | 7a964fe3de94b0fb9cece510dc6b7d5f422c54ba901ed2859a6a4ab16c1d2393 | 30 |
| Event Id (event_id) | StQTIfgQvsiuodkZfwMQ1w== | 31 |
