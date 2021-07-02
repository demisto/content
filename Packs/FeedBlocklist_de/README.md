Use the Blocklist.de feed integration to fetch indicators from the daily Threat Feed and Custom feeds. 
When you configure your servers, you can use this information to reject a connection because of the indicators received from the Blocklist.de feed.


## Custom Feeds

You can connect to a custom Blocklist.de feed by specifying the services from which to process indicators.

| Feed | Description |
| ---- | ----------- |
| all | All IP addresses that have attacked one of Blocklist.de's customers/servers in the last 48 hours. |
| apache | All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks. |
| bots | All IP addresses reported within the last 48 hours as having run attacks attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = they has posted a Spam-Comment on a open Forum or Wiki). |
| bruteforcelogin | All IP addresses which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins. |
| ftp | All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP. |
| imap | All IP addresses which have been reported within the last 48 hours for attacks on the IMAP, SASL, or POP3 services. |
| mail | All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix |
| sip | All IP addresses that tried to login in to a SIP-, VOIP- or Asterisk-Server and are included in the IPs-List from http://www.infiltrated.net/  |
| ssh | All IP addresses which have been reported within the last 48 hours as having run attacks on the SSH service. |
| strongips | All IP addresses which are older then 2 month and have more then 5.000 attacks. |
