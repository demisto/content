Common Okta IAM code that will be appended into the Okta IAM integrations when it's deployed.

This module holds the shared implementation behind the Okta IAM integrations:

- `Okta IAM` (in the `Okta` pack)
- `OktaIAMStandardConnector` (in the `OktaStandardConnector` pack)

Both integrations are thin shims that call `run_okta_iam_integration()`.

The module imports `IAMApiModule` internally, so the vendor-neutral IAM primitives
(`IAMUserProfile`, `IAMActions`, `IAMErrors`) remain available to the Okta IAM code
without adding Okta-specific symbols to the shared `IAMApiModule`.
