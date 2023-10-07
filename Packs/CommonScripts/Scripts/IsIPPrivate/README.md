The script takes one or more IP addresses and checks whether they're in the private IP ranges defined in the *PrivateIPsListName* argument. By default, the *PrivateIPsListName* argument will use the Cortex XSOAR list called "PrivateIPs".
The list can be modified, and by default uses the ranges defined by the Internet Assigned Numbers Authority (IANA). The following are the default CIDR ranges for private IPv4 addresses:
  - 10.0.0.0/8 (range: 10.0.0.0 to 10.255.255.255)
  - 172.16.0.0/12 (range: 172.16.0.0 to 172.31.255.255)
  - 192.168.0.0/16 (range: 192.168.0.0 to 192.168.255.255)

In addition to ranges, it's also possible to add specific IP addresses to the list. You may also tag IPs or IP ranges by adding a comma after the IP or range, and then adding the tag that you want to tag the corresponding IP indicators with.