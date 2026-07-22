## Feodo Tracker IP Blocklist Feed

#### Create an Auth Key for abuse.ch
> Note: If you already have a profile, you can skip steps 1 and 2.

1. Sign up for an abuse.ch account. You can do this easily by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
  
2. Once you are authenticated on abuse.ch, ensure that you connect at least one additional authentication provider. This will ensure that you have access to abuse.ch platforms, even if one of the authentication providers you use shuts down (yes, it happened with Twitter!)

3. Ensure that you hit the "Save profile" button. In the "Optional" section, you can now generate an "Auth-Key". This is your personal Auth-Key that you can now use in the integration.

### Currently Active
- Dridex, Heodo (aka Emotet) and TrickBot botnet command & control servers (C&Cs) reside on compromised servers and servers that have been rent and setup by the botnet herder itself for the sole purpose of botnet hosting. 
- Feodo Tracker offers a bloc klist of IP addresses that are associated with such botnet C&Cs that can be used to detect and block botnet C2 traffic from infected machines towards the internet. 
- An IP address will only get added to the block list if it responds with a valid botnet C2 response. However, a botnet C2 may go offline later.
