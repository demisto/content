The X509 Certificate Pack provides additional capabilities for handling X509 Certificate in Cortex XSOAR. This includes a new **Certificate** Indicator Type and scripts to parse and check X509 Certificate reputations.

##### What does this pack do?
- Provides an additional **Certificate** Indicator Type
- Provides a **Certificate** Indicator Layout
- Provides a script to extract X509 Certificate properties from a file or a PEM encoded string (**!CertificateExtract**)
- Provides a script to check the reputation of X509 certificates performing important security controls and validations on the cert against best practices. (**!CertificateReputation**)