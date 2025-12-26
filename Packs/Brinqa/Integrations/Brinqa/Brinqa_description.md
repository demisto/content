  # BrinqaQL Integration
  https://docs.brinqa.com/docs/brinqa-api/

  Authentication & MFA Limitation
  The integration uses username/password authentication to obtain a token from Brinqa’s /api/auth/login endpoint.
  Important: If Multi-Factor Authentication (MFA) is enabled for the user or service account, this integration will not work, because MFA requires an interactive challenge that cannot be satisfied by API calls.
  Recommendation:

  Use a dedicated service account without MFA for automation purposes.
  Apply least-privilege principles and strong password policies for that account.

  Installation & Setup

  1.Install from Marketplace (or upload this pack manually).
  2.Add an instance of the integration:

  URL: Your Brinqa base URL (e.g., https://<instance>.brinqa.com).
  Credentials: Username/Password (a service account is recommended).
  Trust & Certificates:

  3.Configure proxy if your environment requires outbound proxy.

  4.Ensure MFA is disabled for the account used.
  5.Save and run Test from the Integration instance.