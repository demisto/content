Blueliv ThreatCompass systematically looks for information about companies,products, people, brands, logos, assets, technology and other information, depending on your needs. Blueliv ThreatCompass allows you to monitor and track all this information to keep your data, your
organization and its employees safe

## Configure Blueliv ThreatCompass on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Blueliv ThreatCompass.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL (e.g. `https://demisto.blueliv.com/api/v2` ) | False |
| credentials | Username | False |
| organization | Organization ID | True |
| type | Module Type | True |
| module | Module ID | True |
| unsecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| fetch_limit | Fetch Limit \(Max.\- 200, Recommended less than 50\) | False |
| fetch_status | Fetch resource status \(POSITIVE, NEGATIVE...\) | False |
| first_fetch_time | First fetch time | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### blueliv-resource-all
***
Recovers all resources from the module.


#### Base Command

`blueliv-resource-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| startDate | Minimum date to recover resources. Formats: yyyy-mm-dd or yyyy-mm-ddThh:mm:ss | Optional | 
| finalDate | Maximum date to recover resources. Formats: yyyy-mm-dd or yyyy-mm-ddThh:mm:ss | Optional | 
| page | Results page to get. For each page, there are {limit} resources. | Optional | 
| limit | Maximum number of resources to recover | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BluelivThreatCompass | Unknown | List object of recovered resources | 


#### Command Example
```!blueliv-resource-all limit=10```

#### Context Example
```
{
    "BluelivThreatCompass": {
        "DataLeakage": [
            {
                "analysis_calc_result": "POSITIVE",
                "analysis_result": "POSITIVE",
                "analysis_user_result": "POSITIVE",
                "changed_at": 1589634898000,
                "checked_at": 1589634898000,
                "content_type": "text/html;charset=utf-8",
                "countries_id": "US",
                "created_at": 1589634898000,
                "domain_type": "SOCIAL_NETWORK",
                "fav": "USER_STARRED",
                "file": "2020/5/16/10712044.html",
                "followedUp": false,
                "history": [],
                "id": 10712044,
                "issued": false,
                "labels": [
                    {
                        "id": 1306,
                        "name": "Confidential",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 205,
                        "name": "TopScribdDocsSearch",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "en",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "falabella.com.pe",
                "search_words": [
                    "falabella.com.pe"
                ],
                "title": "TOTUS SEDE SJM FINAL.doc | Internet Protocols | Transmission Control Protocol",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://www.scribd.com/document/461608373",
                "user_rating": 3
            },
            {
                "analysis_calc_result": "POSITIVE",
                "analysis_result": "POSITIVE",
                "changed_at": 1589634865000,
                "checked_at": 1589634865000,
                "content_type": "text/html;charset=utf-8",
                "countries_id": "US",
                "created_at": 1589634865000,
                "domain_type": "SOCIAL_NETWORK",
                "fav": "NOT_STARRED",
                "file": "2020/5/16/10712019.html",
                "followedUp": false,
                "history": [],
                "id": 10712019,
                "issued": false,
                "labels": [
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 205,
                        "name": "TopScribdDocsSearch",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "en",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "falabella.com",
                "search_words": [
                    "falabella.com"
                ],
                "title": "CASO FALABELLA | America latina | Marketing",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://www.scribd.com/document/461631347",
                "user_rating": 0
            },
            {
                "analysis_calc_result": "POSITIVE",
                "analysis_result": "POSITIVE",
                "changed_at": 1589634865000,
                "checked_at": 1589634865000,
                "content_type": "text/html;charset=utf-8",
                "countries_id": "US",
                "created_at": 1589634865000,
                "domain_type": "SOCIAL_NETWORK",
                "fav": "NOT_STARRED",
                "file": "2020/5/16/10712020.html",
                "followedUp": false,
                "history": [],
                "id": 10712020,
                "issued": false,
                "labels": [
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 205,
                        "name": "TopScribdDocsSearch",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "en",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "falabella.com",
                "search_words": [
                    "falabella.com"
                ],
                "title": "tipos de Ventas ejemplos.docx",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://www.scribd.com/document/461606657",
                "user_rating": 0
            },
            {
                "analysis_calc_result": "INFORMATIVE",
                "analysis_result": "INFORMATIVE",
                "changed_at": 1589633157000,
                "checked_at": 1589633157000,
                "content_type": "text/html",
                "countries_id": "GB",
                "created_at": 1589633157000,
                "domain_type": "UNKNOWN",
                "fav": "NOT_STARRED",
                "followedUp": false,
                "history": [],
                "id": 10711255,
                "issued": false,
                "labels": [
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 1864,
                        "name": "VDocumentsSite",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "pt",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "linio",
                "search_words": [
                    "linio"
                ],
                "title": "T\u0623\u2030RMINOS Y CONDICIONES - LINIO MARKETPLACE PREMIUM amp;Cs/20190501_T\u0622\u00a0 asociados (ejemplo: seguro,",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://vdocuments.site/trminos-y-condiciones-linio-marketplace-premium-ampcs20190501t-asociados.html",
                "user_rating": 0
            },
            {
                "analysis_calc_result": "INFORMATIVE",
                "analysis_result": "INFORMATIVE",
                "changed_at": 1589633149000,
                "checked_at": 1589633149000,
                "content_type": "text/html",
                "countries_id": "IN",
                "created_at": 1589633149000,
                "domain_type": "UNKNOWN",
                "fav": "NOT_STARRED",
                "followedUp": false,
                "history": [],
                "id": 10711254,
                "issued": false,
                "labels": [
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 1863,
                        "name": "VDocumentsMX",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "pt",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "linio",
                "search_words": [
                    "linio"
                ],
                "title": "T\u0623\u2030RMINOS Y CONDICIONES - LINIO MARKETPLACE PREMIUM amp;Cs/20190501_T\u0622\u00a0 asociados (ejemplo: seguro,",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://vdocuments.mx/trminos-y-condiciones-linio-marketplace-premium-ampcs20190501t-asociados.html",
                "user_rating": 0
            },
            {
                "analysis_calc_result": "INFORMATIVE",
                "analysis_result": "INFORMATIVE",
                "changed_at": 1589633137000,
                "checked_at": 1589633137000,
                "content_type": "text/html",
                "countries_id": "DE",
                "created_at": 1589633137000,
                "domain_type": "UNKNOWN",
                "fav": "NOT_STARRED",
                "followedUp": false,
                "history": [],
                "id": 10711253,
                "issued": false,
                "labels": [
                    {
                        "id": 1862,
                        "name": "FDocumentsWorld",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "pt",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "linio",
                "search_words": [
                    "linio"
                ],
                "title": "T\u0623\u2030RMINOS Y CONDICIONES - LINIO MARKETPLACE PREMIUM amp;Cs/20190501_T\u0622\u00a0 asociados (ejemplo: seguro,",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://fdocuments.net/document/trminos-y-condiciones-linio-marketplace-premium-ampcs20190501t-asociados.html",
                "user_rating": 0
            },
            {
                "analysis_calc_result": "POSITIVE",
                "analysis_result": "POSITIVE",
                "changed_at": 1589633026000,
                "checked_at": 1589633026000,
                "content_type": "text/html",
                "countries_id": "DE",
                "created_at": 1589633026000,
                "domain_type": "UNKNOWN",
                "fav": "NOT_STARRED",
                "followedUp": false,
                "history": [],
                "id": 10711233,
                "issued": false,
                "labels": [
                    {
                        "id": 1861,
                        "name": "FDocumentsSpain",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "es",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "sodimac",
                "search_words": [
                    "sodimac"
                ],
                "title": "Sodimac Chile 18.151 trabajadores 617.398 horas destinadas a capacitaci\u0623\u00b3n en 2017. ... productividad",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://fdocuments.es/document/sodimac-chile-18151-trabajadores-617398-horas-destinadas-a-capacitacin-en-2017.html",
                "user_rating": 0
            },
            {
                "analysis_calc_result": "INFORMATIVE",
                "analysis_result": "INFORMATIVE",
                "changed_at": 1589633026000,
                "checked_at": 1589633026000,
                "content_type": "text/html",
                "countries_id": "DE",
                "created_at": 1589633026000,
                "domain_type": "UNKNOWN",
                "fav": "NOT_STARRED",
                "followedUp": false,
                "history": [],
                "id": 10711234,
                "issued": false,
                "labels": [
                    {
                        "id": 1861,
                        "name": "FDocumentsSpain",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "es",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "sodimac",
                "search_words": [
                    "sodimac"
                ],
                "title": "Emisi\u0623\u00b3n de Bonos Ordinarios Fuente: Organizaci\u0623\u00b3n Corona y Sodimac Corporativo, 1Capital IQ Agosto",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://fdocuments.es/document/emisin-de-bonos-ordinarios-fuente-organizacin-corona-y-sodimac-corporativo.html",
                "user_rating": 0
            },
            {
                "analysis_calc_result": "POSITIVE",
                "analysis_result": "POSITIVE",
                "changed_at": 1589633026000,
                "checked_at": 1589633026000,
                "content_type": "text/html",
                "countries_id": "DE",
                "created_at": 1589633026000,
                "domain_type": "UNKNOWN",
                "fav": "NOT_STARRED",
                "followedUp": false,
                "history": [],
                "id": 10711235,
                "issued": false,
                "labels": [
                    {
                        "id": 1861,
                        "name": "FDocumentsSpain",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "es",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "sodimac",
                "search_words": [
                    "sodimac"
                ],
                "title": "SODIMAC COLOMBIA S.A. - ?\u00b7 empresas emisoras de valores, lo que nos conlleva a presentar a consideraci\u00f3n\u2026",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://fdocuments.es/document/sodimac-colombia-sa-empresas-emisoras-de-valores-lo-que-nos-conlleva-a.html",
                "user_rating": 0
            },
            {
                "analysis_calc_result": "INFORMATIVE",
                "analysis_result": "INFORMATIVE",
                "changed_at": 1589633026000,
                "checked_at": 1589633026000,
                "content_type": "text/html",
                "countries_id": "DE",
                "created_at": 1589633026000,
                "domain_type": "UNKNOWN",
                "fav": "NOT_STARRED",
                "followedUp": false,
                "history": [],
                "id": 10711236,
                "issued": false,
                "labels": [
                    {
                        "id": 1861,
                        "name": "FDocumentsSpain",
                        "type": "MODULE_LABEL"
                    },
                    {
                        "id": 1305,
                        "name": "Public",
                        "type": "MODULE_LABEL"
                    }
                ],
                "language_id": "es",
                "read": false,
                "retweet_info": [],
                "searchPhrase": "sodimac",
                "search_words": [
                    "sodimac"
                ],
                "title": "Programa SCM Update ?\u00b7 en Sodimac. Mauricio Mu\u00f1oz Jefe de log\u00edstica en Cl\u00ednica Alemana. L\u00eda Vera\u2026",
                "tlpStatus": "AMBER",
                "total_retweets": 0,
                "url": "https://fdocuments.es/document/programa-scm-update-en-sodimac-mauricio-munoz-jefe-de-logistica-en-clinica.html",
                "user_rating": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Blueliv DataLeakage info
>|analysis_calc_result|analysis_result|analysis_user_result|changed_at|checked_at|content_type|countries_id|created_at|domain_type|fav|file|followedUp|history|id|issued|labels|language_id|read|retweet_info|searchPhrase|search_words|title|tlpStatus|total_retweets|url|user_rating|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| POSITIVE | POSITIVE | POSITIVE | 1589634898000 | 1589634898000 | text/html;charset=utf-8 | US | 1589634898000 | SOCIAL_NETWORK | USER_STARRED | 2020/5/16/10712044.html | false |  | 10712044 | false | {'id': 1306, 'name': 'Confidential', 'type': 'MODULE_LABEL'},<br/>{'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'},<br/>{'id': 205, 'name': 'TopScribdDocsSearch', 'type': 'MODULE_LABEL'} | en | false |  | falabella.com.pe | falabella.com.pe | TOTUS SEDE SJM FINAL.doc \| Internet Protocols \| Transmission Control Protocol | AMBER | 0 | https://www.scribd.com/document/461608373 | 3 |
>| POSITIVE | POSITIVE |  | 1589634865000 | 1589634865000 | text/html;charset=utf-8 | US | 1589634865000 | SOCIAL_NETWORK | NOT_STARRED | 2020/5/16/10712019.html | false |  | 10712019 | false | {'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'},<br/>{'id': 205, 'name': 'TopScribdDocsSearch', 'type': 'MODULE_LABEL'} | en | false |  | falabella.com | falabella.com | CASO FALABELLA \| America latina \| Marketing | AMBER | 0 | https://www.scribd.com/document/461631347 | 0 |
>| POSITIVE | POSITIVE |  | 1589634865000 | 1589634865000 | text/html;charset=utf-8 | US | 1589634865000 | SOCIAL_NETWORK | NOT_STARRED | 2020/5/16/10712020.html | false |  | 10712020 | false | {'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'},<br/>{'id': 205, 'name': 'TopScribdDocsSearch', 'type': 'MODULE_LABEL'} | en | false |  | falabella.com | falabella.com | tipos de Ventas ejemplos.docx | AMBER | 0 | https://www.scribd.com/document/461606657 | 0 |
>| INFORMATIVE | INFORMATIVE |  | 1589633157000 | 1589633157000 | text/html | GB | 1589633157000 | UNKNOWN | NOT_STARRED |  | false |  | 10711255 | false | {'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'},<br/>{'id': 1864, 'name': 'VDocumentsSite', 'type': 'MODULE_LABEL'} | pt | false |  | linio | linio | Tأ‰RMINOS Y CONDICIONES - LINIO MARKETPLACE PREMIUM amp;Cs/20190501_Tآ  asociados (ejemplo: seguro, | AMBER | 0 | https://vdocuments.site/trminos-y-condiciones-linio-marketplace-premium-ampcs20190501t-asociados.html | 0 |
>| INFORMATIVE | INFORMATIVE |  | 1589633149000 | 1589633149000 | text/html | IN | 1589633149000 | UNKNOWN | NOT_STARRED |  | false |  | 10711254 | false | {'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'},<br/>{'id': 1863, 'name': 'VDocumentsMX', 'type': 'MODULE_LABEL'} | pt | false |  | linio | linio | Tأ‰RMINOS Y CONDICIONES - LINIO MARKETPLACE PREMIUM amp;Cs/20190501_Tآ  asociados (ejemplo: seguro, | AMBER | 0 | https://vdocuments.mx/trminos-y-condiciones-linio-marketplace-premium-ampcs20190501t-asociados.html | 0 |
>| INFORMATIVE | INFORMATIVE |  | 1589633137000 | 1589633137000 | text/html | DE | 1589633137000 | UNKNOWN | NOT_STARRED |  | false |  | 10711253 | false | {'id': 1862, 'name': 'FDocumentsWorld', 'type': 'MODULE_LABEL'},<br/>{'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'} | pt | false |  | linio | linio | Tأ‰RMINOS Y CONDICIONES - LINIO MARKETPLACE PREMIUM amp;Cs/20190501_Tآ  asociados (ejemplo: seguro, | AMBER | 0 | https://fdocuments.net/document/trminos-y-condiciones-linio-marketplace-premium-ampcs20190501t-asociados.html | 0 |
>| POSITIVE | POSITIVE |  | 1589633026000 | 1589633026000 | text/html | DE | 1589633026000 | UNKNOWN | NOT_STARRED |  | false |  | 10711233 | false | {'id': 1861, 'name': 'FDocumentsSpain', 'type': 'MODULE_LABEL'},<br/>{'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'} | es | false |  | sodimac | sodimac | Sodimac Chile 18.151 trabajadores 617.398 horas destinadas a capacitaciأ³n en 2017. ... productividad | AMBER | 0 | https://fdocuments.es/document/sodimac-chile-18151-trabajadores-617398-horas-destinadas-a-capacitacin-en-2017.html | 0 |
>| INFORMATIVE | INFORMATIVE |  | 1589633026000 | 1589633026000 | text/html | DE | 1589633026000 | UNKNOWN | NOT_STARRED |  | false |  | 10711234 | false | {'id': 1861, 'name': 'FDocumentsSpain', 'type': 'MODULE_LABEL'},<br/>{'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'} | es | false |  | sodimac | sodimac | Emisiأ³n de Bonos Ordinarios Fuente: Organizaciأ³n Corona y Sodimac Corporativo, 1Capital IQ Agosto | AMBER | 0 | https://fdocuments.es/document/emisin-de-bonos-ordinarios-fuente-organizacin-corona-y-sodimac-corporativo.html | 0 |
>| POSITIVE | POSITIVE |  | 1589633026000 | 1589633026000 | text/html | DE | 1589633026000 | UNKNOWN | NOT_STARRED |  | false |  | 10711235 | false | {'id': 1861, 'name': 'FDocumentsSpain', 'type': 'MODULE_LABEL'},<br/>{'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'} | es | false |  | sodimac | sodimac | SODIMAC COLOMBIA S.A. - ?· empresas emisoras de valores, lo que nos conlleva a presentar a consideración… | AMBER | 0 | https://fdocuments.es/document/sodimac-colombia-sa-empresas-emisoras-de-valores-lo-que-nos-conlleva-a.html | 0 |
>| INFORMATIVE | INFORMATIVE |  | 1589633026000 | 1589633026000 | text/html | DE | 1589633026000 | UNKNOWN | NOT_STARRED |  | false |  | 10711236 | false | {'id': 1861, 'name': 'FDocumentsSpain', 'type': 'MODULE_LABEL'},<br/>{'id': 1305, 'name': 'Public', 'type': 'MODULE_LABEL'} | es | false |  | sodimac | sodimac | Programa SCM Update ?· en Sodimac. Mauricio Muñoz Jefe de logística en Clínica Alemana. Lía Vera… | AMBER | 0 | https://fdocuments.es/document/programa-scm-update-en-sodimac-mauricio-munoz-jefe-de-logistica-en-clinica.html | 0 |


### blueliv-resource-search
***
Search for a specific resource.


#### Base Command

`blueliv-resource-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Keywords to search in resources text | Optional | 
| status | Comma-separated list of any combination of status: NOT_AVAILABLE, NOT_IMPORTANT, NOT_PROCESSABLE, POSITIVE, NEGATIVE, INFORMATIVE, IMPORTANT | Optional | 
| startDate | Minimum date to recover resources. Formats: yyyy-mm-dd or yyyy-mm-ddThh:mm:ss | Optional | 
| finalDate | Maximum date to recover resources. Formats: yyyy-mm-dd or yyyy-mm-ddThh:mm:ss | Optional | 
| read | What results read status to get. | Optional | 
| limit | Maximum number of resources to recover | Optional | 
| page | Results page to get. For each page, there are {limit} resources. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BluelivThreatCompass | Unknown | List object of recovered resources | 


#### Command Example
``` ```

#### Human Readable Output



### blueliv-resource-search-by-id
***
Recovers all the information of a given resource


#### Base Command

`blueliv-resource-search-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BluelivThreatCompass | Unknown | Object with the information of the recovered resource | 


#### Command Example
```!blueliv-resource-search-by-id id=10712044```

#### Context Example
```
{
    "BluelivThreatCompass": {
        "DataLeakage": {
            "analysis_calc_result": "POSITIVE",
            "analysis_result": "POSITIVE",
            "analysis_user_result": "POSITIVE",
            "changed_at": 1589634898000,
            "checked_at": 1589634898000,
            "content_type": "text/html;charset=utf-8",
            "countries_id": "US",
            "created_at": 1589634898000,
            "domain_type": "SOCIAL_NETWORK",
            "fav": "USER_STARRED",
            "file": "2020/5/16/10712044.html",
            "followedUp": false,
            "history": [],
            "id": 10712044,
            "issued": false,
            "labels": [
                {
                    "id": 1306,
                    "name": "Confidential",
                    "type": "GLOBAL"
                },
                {
                    "id": 1305,
                    "name": "Public",
                    "type": "GLOBAL"
                },
                {
                    "id": 205,
                    "name": "TopScribdDocsSearch",
                    "type": "GLOBAL"
                }
            ],
            "language_id": "en",
            "read": false,
            "retweet_info": [],
            "searchPhrase": "falabella.com.pe",
            "search_words": [
                "falabella.com.pe"
            ],
            "title": "TOTUS SEDE SJM FINAL.doc | Internet Protocols | Transmission Control Protocol",
            "tlpStatus": "AMBER",
            "total_retweets": 0,
            "transform": "TopScribdDocsSearch",
            "url": "https://www.scribd.com/document/461608373",
            "user_rating": 3
        }
    }
}
```

#### Human Readable Output

>### Blueliv DataLeakageinfo
>|analysis_calc_result|analysis_result|analysis_user_result|changed_at|checked_at|content_type|countries_id|created_at|domain_type|fav|file|followedUp|history|id|issued|labels|language_id|read|retweet_info|searchPhrase|search_words|title|tlpStatus|total_retweets|transform|url|user_rating|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| POSITIVE | POSITIVE | POSITIVE | 1589634898000 | 1589634898000 | text/html;charset=utf-8 | US | 1589634898000 | SOCIAL_NETWORK | USER_STARRED | 2020/5/16/10712044.html | false |  | 10712044 | false | {'id': 1306, 'name': 'Confidential', 'type': 'GLOBAL'},<br/>{'id': 1305, 'name': 'Public', 'type': 'GLOBAL'},<br/>{'id': 205, 'name': 'TopScribdDocsSearch', 'type': 'GLOBAL'} | en | false |  | falabella.com.pe | falabella.com.pe | TOTUS SEDE SJM FINAL.doc \| Internet Protocols \| Transmission Control Protocol | AMBER | 0 | TopScribdDocsSearch | https://www.scribd.com/document/461608373 | 3 |


### blueliv-resource-set-status
***
Changes a resource status.


#### Base Command

`blueliv-resource-set-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID | Required | 
| status | New status to assign to the resource | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!blueliv-resource-set-status id=10712044 status=positive```

#### Context Example
```
{}
```

#### Human Readable Output

>Status changed to **positive**

### blueliv-resource-set-label
***
Adds a label to the given resource


#### Base Command

`blueliv-resource-set-label`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID | Required | 
| labelId | Label ID | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### blueliv-resource-set-read-status
***
Mark the result as read or not.


#### Base Command

`blueliv-resource-set-read-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID | Required | 
| read | The read status to set. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!blueliv-resource-set-read-status id=10712044 read=false```

#### Context Example
```
{}
```

#### Human Readable Output

>Read status changed to **false**.

### blueliv-resource-assign-rating
***
Assign tating to a given result.


#### Base Command

`blueliv-resource-assign-rating`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID | Required | 
| rating | Rating to assign to the result. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!blueliv-resource-assign-rating id=10712044 rating=3```

#### Context Example
```
{}
```

#### Human Readable Output

>Rating changed to **3**.

### blueliv-resource-fav
***
Changes the favourite status of a resource.


#### Base Command

`blueliv-resource-fav`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID | Required | 
| fav | The new fav status of the resource. Can be applied to the user, group or general. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!blueliv-resource-fav id=10712044 fav=User```

#### Context Example
```
{}
```

#### Human Readable Output

>Resource fav masked as **User** correctly.

### blueliv-resource-set-tlp
***
Sets a new TLP status to a given resource.


#### Base Command

`blueliv-resource-set-tlp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Resource ID | Required | 
| tlp | The new TLP to assign.  | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


