To use the Accessdata integration specify as a token the domain or the IP address of the Quin-C instance and the EnterpriseAPI Key.
  To get the token follow these steps:
  1. Open the Quin-C UI.
  2. Log in to the Quin-C.
  3. Go to http(s)://_____/api/security/1000/getenterpriseapiguid (specify Quin-C IP and port), which returns an XML like <string xmlns="http://schemas.microsoft.com/2003/10/Serialization/">TOKEN_STRING</string>, where in place of TOKEN_STRING is your EnterpriseAPI Key.
