### IR Violations List
|ID|Policy Name|Display Name|Domain|Actor Name|Target Name|Status|Severity|Policy Type|Category|Title|Root Domain|Event Time|Detected On|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 00000000-0000-0000-0000-000000000001 | Excessive admin privileges | John Doe | rubrikdemo.com |  |  | Open | High | Identity | Identity Hygiene | Engineer |  |  | 2026-03-25T09:29:55.000Z |
| 00000000-0000-0000-0000-000000000002 | Stale MFA not enforced | Jane Smith | rubrikdemo.com |  |  | In Progress | Critical | Identity | Authentication And Secret Management | Analyst |  |  | 2026-03-25T14:30:02.000Z |
| 00000000-0000-0000-0000-000000000003 | Overly permissive IDP configuration |  | rubrikdemo.com |  |  | Open | Medium | Idp | Identity Provider Security |  | rubrikdemo.com |  | 2026-03-25T16:45:30.000Z |
| 00000000-0000-0000-0000-000000000004 | Crowdstrike Alert Integration |  |  | svc sql | ZY1-AD01 | Open | Low | Crowdstrike | Category Unspecified |  |  |  | 2026-03-25T11:08:07.000Z |
| 00000000-0000-0000-0000-000000000005 | Microsoft Defender Alert Integration |  |  | Administrator | ZY1-AD05 | Open | High | Microsoft Defender | Category Unspecified |  |  |  | 2026-03-25T11:23:33.000Z |
| 00000000-0000-0000-0000-000000000006 | Identity Event Monitoring |  |  | svc_lateral | ZY1-DC01 | Open | Critical | Identity Event | Category Unspecified |  |  | 2026-03-25T08:14:30.000Z | 2026-03-25T08:15:00.000Z |

Note: To retrieve the next set of results use, "next_page_token" = hash_token_ir