## KELA Monitor

Fetches the incidents of your KELA Monitor into Cortex XSOAR and lets you list them by incident type.

### How to get the connection data

1. **API Token**: generate it in the KELA platform (system menu). It is sent as the `apiToken` query parameter and is never written to the logs.
2. **Monitor ID**: open your Monitor in the KELA platform and copy the `monitorId` value from the page URL.
3. **Incident types**: choose at least one (hacking discussions, instant messaging, leaked credentials, network vulnerabilities, credit cards, botnets). Each type is fetched with its own position, so adding a type later does not re-fetch the others.

### Good to know

- If the token has no access (403) to some of the selected incident types, those are skipped and the others keep working. If it has no access to any of them, the fetch fails with a clear message. Test tells you which types are forbidden.
- One instance connects to one Monitor. Create one instance per Monitor.
- Sensitive data (passwords, card numbers) is masked by default. It can be disabled with the *Mask sensitive data* option.
- Hacking discussions are fetched as a snippet only, never the full text.
- Hidden and deleted incidents are not created in XSOAR.
- The integration is read-only: it never changes anything in KELA.
- The KELA API allows 1 request per second; the integration paces itself.
