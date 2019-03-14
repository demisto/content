from stix2 import Indicator

indicator = Indicator(name="File hash for malware variant",
                      labels="label-kof",
                      pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']")
print(indicator)