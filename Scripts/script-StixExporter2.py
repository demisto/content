from stix2 import Indicator

type ="File MD5"

sourceSystem = "DBot"

value = "ABC"

indicator = Indicator(name="File hash for malware variant",
                      labels="label-kof",
                      pattern="[file:hashes.md5 = '" + value + "']",
                      source=sourceSystem,
                      allow_custom=True)
print(indicator)