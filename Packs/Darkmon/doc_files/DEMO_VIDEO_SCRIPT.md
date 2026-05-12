# Darkmon Pack — Demo Video Script

**Target length:** 3–5 minutes
**Audience:** Cortex XSOAR Marketplace reviewers + prospective users
**Format:** Screencast with voiceover. Upload to YouTube (unlisted is fine); link goes in the PR description and the pack reviewer comments.

---

## 0. Title card (0:00–0:10)

> "Hi, I'm <name> from Darkmon. This is a quick walkthrough of the Darkmon Threat Intelligence pack for Cortex XSOAR."

Show: Darkmon logo on a clean slide.

---

## 1. What the pack does (0:10–0:40)

Talking points (script, paraphrase freely):

> "Darkmon TIP gathers threat intelligence from the clear, deep, and dark web. This pack turns that intel into XSOAR-native content — one integration with 18 commands, 20 playbooks, 6 incident types, and 11 layouts. It plugs into XSOAR's reputation system so any existing playbook can enrich indicators with Darkmon data, and ships continuous-monitoring jobs for compromised credentials, VIP email leaks, ransomware mentions, brand typosquats, and critical CVEs."

Show: scroll the pack's Marketplace details page (the screenshot `01_pack_details.png` is the same view).

---

## 2. Install (0:40–1:10)

Show on screen:
- Open *Marketplace → search "Darkmon" → Install*
- Wait for "Pack installed" toast

Voiceover:

> "Install is one click from the Cortex Marketplace. The pack is around 2.6 MB and installs in under 30 seconds."

---

## 3. Configure (1:10–2:00)

Show:
- *Settings → Integrations → Darkmon → Add instance*
- Paste API key (use a redacted key on-screen)
- Leave API Base URL at default
- Click **Test** → "Success"
- Save & exit

Voiceover:

> "Configuration is just an API key. The base URL defaults to our production endpoint; override it only if you're targeting a dev or staging tenant. Test confirms the integration can talk to Darkmon."

---

## 4. Enrichment via reputation (2:00–2:40)

Show in the Playground / War Room:
- Run `!ip 1.2.3.4` (use a real IP your tenant has data for; `1.2.3.4` is a placeholder)
- Show the resulting markdown table + the right-side context panel with `DBotScore` and `Common.IP`

Voiceover:

> "Reputation commands are wired into XSOAR's standard DBotScore and Common.<Type> contract. That means any existing playbook that already does indicator enrichment will start using Darkmon data the moment this integration is enabled — no playbook rewrites."

---

## 5. Discovery commands (2:40–3:20)

Show two Darkmon-specific commands:
- `!dmontip-get-cve size=5` — show the CVE table
- `!dmontip-get-compromised type=accounts size=5` — show the compromised-account table with `***` in the password column

Voiceover:

> "Beyond enrichment, you can pull live Darkmon feeds directly. Here are five recent CVEs with CVSS and exploitation status, and here are five recent compromised account leaks — passwords redacted by default per the integration's compliance posture."

---

## 6. Playbooks + monitoring jobs (3:20–4:20)

Show:
- *Playbooks → filter "Darkmon"* → click *Darkmon - Compromised Credentials Sweep*
- Show the playbook graph (screenshot `03_playbook_compromised.png` matches)
- Mention the cron: every 4 hours
- Optionally: scroll the playbook list briefly

Voiceover:

> "Continuous monitoring is built in. The Compromised Credentials Sweep runs every four hours, fetches new leaks, filters them to the customer's domains using an XSOAR list, dedupes against a state list, and opens one incident per affected account. Five other jobs cover VIP emails hourly, ransomware mentions every six hours, brand-targeted newly-registered domains daily, critical CVEs daily, and an employee auto-disable flow."

---

## 7. Incident response (4:20–4:50)

Show:
- Open one of the incident-response playbooks, e.g. *Darkmon - Compromised Account Response*
- Briefly show the provider switchboard structure

Voiceover:

> "Incident-response playbooks call provider-agnostic sub-playbooks for notification, indicator blocking, and identity actions, so the same content works whether the customer runs PAN, Fortinet, Slack, Teams, AD, Okta, or Azure AD — no forking."

---

## 8. Close (4:50–5:00)

Show: pack README or `darkmon.com`.

Voiceover:

> "That's the Darkmon pack. Documentation is on `darkmon.com` and `support@darkmon.com` for questions. Thanks for reviewing."

---

## Recording checklist

- [ ] Browser zoom 110–125% so text reads on YouTube at 720p.
- [ ] Hide bookmarks bar / personal tabs.
- [ ] Use a fresh XSOAR session so no "(Modified)" or unsaved indicators clutter the UI.
- [ ] If the tenant has prior War Room scrollback, scroll past it or use a fresh investigation.
- [ ] Mic close, gain consistent, no fan noise.
- [ ] Export at 1080p, 30 fps. Upload as unlisted to YouTube. Paste the link into the PR body.
