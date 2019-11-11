To use Quin-C integration you should specify domain or IP of Quin-C instance and EnterpriseAPI Key as token.
  To get token follow these steps:
  1. Open Quin-C UI
  2. Log in to the Quin-C
  3. Go to https://X.X.X.X/api/security/1000/getenterpriseapiguid (where X.X.X.X is Quin-C IP and port) that will return XML like <string xmlns="http://schemas.microsoft.com/2003/10/Serialization/">TOKEN_STRING</string> where in place of TOKEN_STRING will be your EnterpriseAPI Key