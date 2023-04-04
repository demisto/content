# Barracuda Email Protection

### The world′s most comprehensive email protection, made radically easy.

See https://www.barracuda.com/products/email-protection for more information on this prouct.


## Configuring the Barracuda Mail Syslog

To configure the Mail syslog, using the Barracuda Email Security Gateway web interface, navigate to the *ADVANCED > Advanced Networking* page and enter the IP address and port of the syslog server to which syslog data related to mail flow should be sent. You can also specify the protocol – TCP or UDP – over which syslog data should be transmitted. TCP is recommended.

Syslog data is the same information as that used to build the Message Log in the Barracuda Email Security Gateway and includes data such as the connecting IP Address, envelope 'From' address, envelope 'To' address, and the spam score for the messages transmitted. This syslog data appears on the mail facility at the debug priority level on the specified syslog server. As the Barracuda Email Security Gateway uses the syslog messages internally for its own message logging, it is not possible to change the facility or the priority level. See the *Syslog* section of the *ADVANCED > Troubleshooting* page in the Barracuda Email Security Gateway web interface to open a window and view the Mail syslog output.

If you are running syslog on a UNIX machine, be sure to start the syslog daemon process with the “-r” option so that it can receive messages from sources other than itself. Windows users will have to install a separate program to utilize syslog since the Windows OS doesn’t include syslog capability. Kiwi Syslog is a popular solution, but there are many others are available to choose from, both free and commercial.

Syslog messages are sent via either TCP or UDP to the standard syslog port of 514. If there are any firewalls between the Barracuda Email Security Gateway and the server receiving the syslog messages, make sure that port 514 is open on the firewalls.
