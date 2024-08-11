Predict phishing URLs using a pre-trained model.

## Security Recommendations
---

This script uses the [Rasterize](https://xsoar.pan.dev/docs/reference/integrations/rasterize) integration. If this script is used to rasterize untrusted URLs, we strongly recommend following the security recommendations included at the [Rasterize Documentation](https://xsoar.pan.dev/docs/reference/integrations/rasterize).

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml |
| Cortex XSOAR Version | 6.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

Phishing - Machine Learning Analysis

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
| defaultRequestProtocol | The protocol to use when calling the URLs. This argument effects the calls sent by the model only and has no effect on the rasterize or whois commands. |
| debug | Whether to enter debug mode. |
| reliability | Reliability of the source providing the intelligence data. |

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
```!DBotPredictURLPhishing urls="http://google.com"```
### Context Example
```json
{
  "DBotPredictURLPhishing": [
    {
      "FinalVerdict": "Benign",
      "TopMajesticDomain": "True",
      "URL": "http://google.com"
    }
  ]
}
```

### Human Readable Output

>### Phishing prediction summary for URLs
>|URL|Final Verdict|
>|---|---|
>| http://google.com | **Benign - whitelisted** |

