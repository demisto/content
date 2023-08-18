## Supported Dispositions
CheckPhish classifies URLs by the following dispositions (categories).
- Zero-day phishing
- Tech support scams
- Gift card scams
- Survey scams
- Adult websites
- Drug pharmacy (Drug Spam) websites
- Illegal/rogue streaming sites
- Gambling websites
- Hacked Websites
- Cryptojacking/cryptomining

## Sending URLs to Check
There is no limit to the number of URLs you can send in each call. The limit is determined by your API privileges. using commas between the URLs, 
for Example: www.demisto.com,www.google.com,www.youtube.com

## Modify Severity Levels
You can modify the severity levels of any disposition received from CheckPhish. We recommend the following default parameters:\
- Good = clean\
- Suspicious = drug_spam, gambling, hacked_website, streaming, suspicious\
- Bad = cryptojacking, phish, likely_phish, scam\

**Note**: The worst category in which a label is included will be the effective one. 

Notice: Submitting indicators using the following commands of this integration might make the indicator data publicly available.
- ***url***
- ***CheckPhish-check-urls***
See the vendor’s documentation for more details.
