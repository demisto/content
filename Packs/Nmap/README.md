Nmap scans your network and discovers not only everything connected to it, but also a wide variety of information about what's connected, what services each host is operating, and so on. It helps you protect your network from hackers, because it allows you to quickly spot any security vulnerabilities in your systems.

## What does this pack do?
Runs nmap scans with the given parameters.

This pack includes 2 out-of-the-box playbooks that act as sub-playbooks that performs:

- A single port Nmap scan and returns the results to the parent playbook.
- An Nmap scan and compares the results against a regular expression to determine a match. This could be used to look for OpenSSH versions or other OS information found in the banner.