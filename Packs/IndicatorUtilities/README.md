A set of scripts adding functionality to Threat Intel Management.

# What's in this pack

This pack contains three scripts;

#### ImportFromMinemeld

Imports manually created indicators from Minemeld lists, while preserving
comments and TLP.

#### WhiteListCIDR

Compares IP indicators against matching CIDR indicators and tags in the case of overlap - this 
allows you to use a dynamic source of CIDR indicators as a whitelist.

#### WhiteListDomainGlob

Compares domains and URLs against domainGlob indicators and tags in the case of a match - this 
allows you to use a dynamic source of domainGlob indicators as a whitelist.

