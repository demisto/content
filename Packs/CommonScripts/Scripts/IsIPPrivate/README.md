The IsIPPrivate script takes a list of IP addresses and checks whether they're in the private IP ranges defined in the PrivateIPRangeList argument. by default, the PrivateIPRangeList argument will use the XSOAR list called "PrivateIPRanges".
  The list can be modified, and by default uses the ranges defined by the Internet Assigned Numbers Authority (IANA). The following are the default CIDR ranges for private IPv4 addresses:
  - 10.0.0.0/8 (range: 10.0.0.0 to 10.255.255.255)
  - 172.16.0.0/12 (range: 172.16.0.0 to 172.31.255.255)
  - 192.168.0.0/16 (range: 192.168.0.0 to 192.168.255.255)