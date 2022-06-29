Predict phishing URLs using a pre-trained model.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| urls | Space-separated list of URLs. |
| emailBody | Body of the email for URL extraction. |
| emailHTML | HTML of the email for URL extraction. |
| maxNumberOfURL | Maximum number of extracted URLs on which to run the model. |
| forceModel | Whether to force the model to run if the URL belongs to the whitelist. If True, the model will run in every case. If False, the model will run only if the URL does not belong to the whitelist. |
| resetModel | Whether to reset the model to the model existing in Docker. |
| debug | Whether to enter debug mode. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPredictURLPhishing.URL | URL on which the model ran. | String |
| DBotPredictURLPhishing.FinalVerdict | Final verdict of the URL. | String |
| DBotPredictURLPhishing.UseOfSuspiciousLogo | Whether a logo \(from our list of top most use company for phishing\) has been fraudulently used. Our predefined list of logos is: Paypal, Instagram, Gmail, Outlook, Linkedin, Facebook, Ebay, amazon, Google, Microsoft. | String |
| DBotPredictURLPhishing.HasLoginForm | Whether there is a login form in the HTML. Usually phishing attacks aim to steal credentials from the victim and attackers using login forms to retrieve this information. | String |
| DBotPredictURLPhishing.URLStaticScore | Probability for the URL to be malicious based only on the URL syntax. | Number |
| DBotPredictURLPhishing.BadSEOQuality | Whether the domain has a good search engine optimization. Malicious domains tend to have a poor SEO. | String |
| DBotPredictURLPhishing.NewDomain | Whether the domain is younger than 6 months. New domains tend to be malicious. | String |
| DBotPredictURLPhishing.TopMajesticDomain | Whether the domain belongs to the top Majestic domain list. If it does, we will always consider this domain as benign. | String |
| DBotScore.Score | Severity score. | Number |


## Script Examples
### Example command
```!DBotPredictURLPhishing urls=google.com```
### Context Example
```json
{}
```

### Human Readable Output

>### Phishing prediction summary for URLs
>|URL|Final Verdict|
>|---|---|
>| http://google.com | **Benign - whitelisted** |

