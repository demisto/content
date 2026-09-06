## SOCRadar IoC Enrichment
## SOCRadar IoC Enrichment

### Overview & Key Features
The SOCRadar IoC Enrichment integration leverages an **Advanced Intelligence API** to provide deep threat context, categorization, and comprehensive analysis for indicators of compromise (IP, Domain, URL, Hash).

* **Rich Threat Context & Categorization:** Identifies service types and malicious flags (e.g., Malware, Threat Actor, Tor, VPN, Proxy, CDN, Cloud, Scanner).
* **Signal Strength:** Evaluates IoC reliability and maliciousness on a scale from *Very Strong* (block immediately) to *Noisy* (high false-positive rate).
* **Confidence Levels:** Provides cross-source validation confidence (Very High, High, Medium, Low).
* **Threat Attribution:** Associates indicators with known campaigns, threat actors, malware families, and targeted industries/countries.
* **Historical Data & Relations:** Delivers a timeline of historical events, activity labels (last 1 to 90 days), and relations across premium threat feeds.
* **AI-Generated Insights (Optional):** Integrates with SOCRadar Copilot to provide AI-driven, human-readable threat intelligence context.

### Prerequisites & Licensing
* **Advanced Intelligence API:** This module operates beyond the standard SOCRadar platform capabilities. To use this integration, your API key must be specifically authorized for IoC Enrichment.
* **Standalone Purchase:** This service is licensed separately. You can add it to your existing SOCRadar subscription or purchase it as a **standalone key**, allowing you to use the API completely independently of a platform membership.
* **Purchase & Support:** To upgrade your existing API key, request pricing, or purchase a standalone key, please contact our support team at **support@socradar.io**.

### Configuration Notes & Performance
* **AI Insights Impact:** You can enable AI-generated insights via the integration configuration (`Include AI Insights`). **Warning:** Enabling this feature significantly increases API response times (2-5x slower) due to backend AI processing. It is highly recommended to keep this disabled for performance-critical or high-volume automated playbooks.
* **Rate Limits:** The API enforces a rate limit (e.g., 1 request per second). If the limit is exceeded, the integration will return a `Rate limit exceed` error. Please ensure your query volume aligns with your license limits.