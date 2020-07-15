The Threat Context module provides SOC, Incident Response and Threat Intelligence teams with continuously updated and intuitive information around threat actors, campaigns, malware indicators, attack patterns, tools, signatures and CVEs.
This integration was integrated and tested with version xx of Blueliv ThreatContext
## Configure Blueliv ThreatContext on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Blueliv ThreatContext.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://demisto.blueliv.com/api/v2\) | False |
| credentials | Username | False |
| unsecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### blueliv-authenticate
***
Authenticate and get the API token


#### Base Command

`blueliv-authenticate`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| token | string | Authentication token | 


#### Command Example
```!blueliv-authenticate```

#### Context Example
```
{}
```

#### Human Readable Output

>981bfb934723091e606c0e35998217bdcafc8697d1a6d0911ff5b2fedb5a16c

### blueliv-tc-malware
***
Gets information about malware by ID


#### Base Command

`blueliv-tc-malware`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash_id | Internal Blueliv's malware hash ID | Optional | 
| hash | Malware file hash to search for | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| malware.hash.sha256 | Unknown | File SHA256 | 
| malware.hash.sha1 | Unknown | File SHA1 | 
| malware.hash.md5 | Unknown | File MD5 | 
| malware.type | Unknown | Malware Type | 
| malware.hasCandC | unknown | If there is a C&amp;C associated | 
| malware.memory | Unknown | Malware memory | 
| malware.procMemory | Unknown | Malware proc memory | 
| malware.analysisStatus | Unknown | Malware analysis status | 
| malware.dropped | Unknown | Malware dropped | 
| malware.buffers | Unknown | Malware buffers | 
| malware.hasNetwork | Unknown | If the malware has Network informations | 
| malware.risk | Unknown | Malware associated risk | 
| malware.campaigns | Unknown | Malware related campaigns | 
| malware.campaignIds | Unknown | Malware related campaigns internal IDs | 
| malware.signatures | Unknown | Malware signatures | 
| malware.sigantureIds | Unknown | Malware sigantures internal IDs | 
| malware.threatActors | Unknown | Malware threat actors | 
| malware.threatActorIds | Unknown | Malware threat actors internal IDs | 
| malware.sources | Unknown | Malware sources | 
| malware.sourceIds | Unknown | Malware sources internal IDs | 
| malware.tags | Unknown | Malware tags | 
| malware.tagIds | Unknown | Malware tags internal IDs | 
| malware.crimeServers | Unknown | Malware related crime servers | 
| malware.crimeServerIds | Unknown | Malware crime servers internal IDs | 
| malware.fqdns | Unknown | Malware FQDNs | 
| malware.fqdnIds | Unknown | Malware FQDNs internal IDs | 
| malware.types | Unknown | Malware types | 
| malware.typeIds | Unknown | Malware types internal IDs | 
| malware.sparks | Unknown | Malware sparks | 
| malware.sparkIds | Unknown | Malware sparks internal IDs | 
| malware.ips | Unknown | Malware IPs | 
| malware.ipIds | Unknown | Malware IPs internal IDs | 


#### Command Example
```!blueliv-tc-malware hash=ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1```

#### Context Example
```
{
    "malware": {
        "analysisStatus": "FINISHED_SUCCESSFULLY",
        "buffers": false,
        "campaignIds": "",
        "campaigns": 0,
        "crimeServers": 0,
        "crimeserverIds": "",
        "dropped": false,
        "fileType": "PE",
        "fqdnIds": "",
        "fqdns": 0,
        "hasCandC": false,
        "hasNetwork": true,
        "hash": {
            "md5": "36a40cc55e2ffe7d44d007c6e37afd7f",
            "sha1": "5c0be68316ce77584a7b966ff40e7d61a8a98055",
            "sha256": "ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1"
        },
        "ipIds": "92269700,100333500,",
        "ips": 2,
        "memory": false,
        "procMemory": false,
        "risk": 7,
        "signatureIds": "",
        "signatures": 0,
        "sourceIds": "1958672,",
        "sources": 1,
        "sparkIds": "",
        "sparks": 0,
        "tagIds": "",
        "tags": 0,
        "threatActorIds": "",
        "threatActors": 0,
        "typeIds": "62,",
        "types": 1
    },
    "threatContext": {
        "hasResults": "true"
    }
}
```

#### Human Readable Output

>### Blueliv Malware file info
>|analysis_date|analysis_delivered_date|analysis_signatures|analysis_status|at_afapi|behaviors|buffers|cerberus|created_at|created_at_afapi|dropped|file_type|first_seen|has_c_and_c|has_network|has_other_urls|hash|id|ioa|ioc_link|last_risk_scoring|last_seen|links|malfind|malicious_category|md5|memory|metadata|number_properties|pcap|priority_at_afapi|proc_memory|properties|report|risk|sample|scans_link|seen_at_analyzer|sha1|sha256|sha512|slugs_tags|sources_representation|subtype|target|tlp|type|types_names|updated_at|updated_at_afapi|uuid|version|vt_matches|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-06-15T16:30:22.770000Z | 2020-06-15T16:22:00.220000Z | Signature severity - Informative,<br/>Detected dead hosts,<br/>Detects the presence of a Debugger,<br/>Clipboard access capabilities,<br/>Creates Mutants,<br/>Detected cryptographic algorithm,<br/>Has the ability to retrieve keyboard strokes,<br/>Has the ability to reboot/shutdown the Operating System,<br/>Detected Packer,<br/>Detected PE anomalies,<br/>Reads configuration files,<br/>Loads Visual Basic Runtime environment,<br/>Detected injected process,<br/>Signature severity - Suspicious,<br/>Allocates memory with Read-Write-Execute permissions,<br/>Attempts to delay the analysis task,<br/>Clipboard modification capabilities,<br/>Spawns processes,<br/>Classified by Blueliv,<br/>Allocates memory with write/execute permissions in a remote process,<br/>Machine Learning scoring,<br/>Detected Keylogger,<br/>Detected Autorun Persistence,<br/>Writes data to a remote process,<br/>Detected RunPE injection technique,<br/>VirusTotal matches,<br/>Signature severity - Malicious | FINISHED_SUCCESSFULLY | true |  | false | 0.9645 | 2020-06-15T16:27:20.074884Z | 2020-06-15T16:21:38.209000Z | false | PE | 2020-06-15T16:21:38.209000Z | false | true | false | ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1 | 59770710 | ip: 25.20.116.113,<br/>103.143.173.25,<br/>192.168.56.102<br/>url: http://uk.ask.com/favicon.ico,<br/>http://www.priceminister.com/,<br/>http://ru.wikipedia.org/,<br/>http://www.merlin.com.pl/favicon.ico,<br/>http://www.cnet.com/favicon.ico,<br/>http://www.certificadodigital.com.br/repositorio/serasaca/crl/SerasaCAII.crl0,<br/>http://search.nifty.com/,<br/>http://ns.adobe.com/exif/1.0/,<br/>http://www.shopzilla.com/,<br/>http://crl.chambersign.org/publicnotaryroot.crl0,<br/>http://search.goo.ne.jp/,<br/>http://fr.wikipedia.org/favicon.ico,<br/>http://busca.estadao.com.br/favicon.ico,<br/>http://search.hanafos.com/favicon.ico,<br/>http://search.chol.com/favicon.ico,<br/>http://search.livedoor.com/favicon.ico,<br/>http://amazon.fr/,<br/>http://www.amazon.co.jp/,<br/>http://www.e-szigno.hu/SZSZ/0,<br/>http://busqueda.aol.com.mx/,<br/>http://search.live.com/results.aspx?FORM=SOLTDF,<br/>http://msdn.microsoft.com/,<br/>http://www.sogou.com/favicon.ico,<br/>http://yellowpages.superpages.com/,<br/>http://www.expedia.com/favicon.ico,<br/>http://crl.chambersign.org/chambersroot.crl0,<br/>http://search.aol.com/,<br/>http://browse.guardian.co.uk/,<br/>http://www.mercadolibre.com.mx/,<br/>http://www.asharqalawsat.com/,<br/>http://www.facebook.com/,<br/>http://search.auone.jp/,<br/>http://www.rtl.de/favicon.ico,<br/>http://search.msn.com/results.aspx?q=,<br/>http://www.microsoft.com.,<br/>http://search.naver.com/favicon.ico,<br/>http://fedir.comsign.co.il/cacert/ComSignAdvancedSecurityCA.crt0,<br/>http://crl.usertrust.com/UTN-USERFirst-NetworkApplications.crl0,<br/>http://en.wikipedia.org/favicon.ico,<br/>http://si.wikipedia.org/w/api.php?action=opensearch,<br/>http://www.signatur.rtr.at/de/directory/cps.html0,<br/>http://udn.com/favicon.ico,<br/>http://rover.ebay.com,<br/>http://search.ebay.fr/,<br/>http://www.univision.com/,<br/>http://pt.wikipedia.org/w/api.php?action=opensearch,<br/>http://www.certplus.com/CRL/class3TS.crl0,<br/>http://it.wikipedia.org/favicon.ico,<br/>http://uk.ask.com/,<br/>http://www.google.co.uk/,<br/>http://cnweb.search.live.com/results.aspx?q=,<br/>http://www.google.cz/,<br/>http://www.google.co.jp/,<br/>http://search.ebay.co.uk/,<br/>http://www.weather.com/,<br/>http://www.taobao.com/favicon.ico,<br/>http://www.news.com.au/favicon.ico,<br/>http://www.priceminister.com/favicon.ico,<br/>http://www.e-me.lv/repository0,<br/>http://video.globo.com/,<br/>http://search.ebay.de/,<br/>http://www.taobao.com/,<br/>http://find.joins.com/,<br/>http://corp.naukri.com/favicon.ico,<br/>http://www.servicios.clarin.com/,<br/>http://localhost,<br/>http://www.rambler.ru/favicon.ico,<br/>http://www.linternaute.com/favicon.ico,<br/>http://ns.adobe.com/photoshop/1.0/,<br/>http://www.etmall.com.tw/,<br/>http://www.amazon.com/gp/search?ie=UTF8,<br/>http://search.live.com/results.aspx?FORM=SO2TDF,<br/>http://www.quovadis.bm0,<br/>http://www.chambersign.org1,<br/>http://www.excite.co.jp/,<br/>http://cs.wikipedia.org/,<br/>http://www.d-trust.net/crl/d-trust_qualified_root_ca_1_2007_pn.crl0,<br/>http://www.gismeteo.ru/favicon.ico,<br/>http://www.cjmall.com/favicon.ico,<br/>http://suche.t-online.de/,<br/>http://www.ya.com/favicon.ico,<br/>http://search.orange.co.uk/favicon.ico,<br/>http://www.trustcenter.de/guidelines0,<br/>http://www.mercadolibre.com.mx/favicon.ico,<br/>http://www.trustcenter.de/crl/v2/tc_class_2_ca_II.crl,<br/>https://ocsp.quovadisoffshore.com0,<br/>http://www.e-trust.be/CPS/QNcerts,<br/>http://ns.adobe.com/tiff/1.0/,<br/>http://www.otto.de/favicon.ico,<br/>http://search.lycos.com/favicon.ico,<br/>http://www.iask.com/,<br/>http://www.arrakis.com/,<br/>http://it.search.dada.net/,<br/>http://support.microsoft.com/kb/9311250,<br/>http://fedir.comsign.co.il/crl/ComSignSecuredCA.crl0,<br/>http://www.microsofttranslator.com/BVPrev.aspx?ref=IE8Activity,<br/>http://search.ebay.es/,<br/>http://search.gamer.com.tw/,<br/>http://busca.igbusca.com.br//app/static/images/favicon.ico,<br/>http://ns.adobe.com/xap/1.0/,<br/>http://www.soso.com/favicon.ico,<br/>http://www.echoworx.com/ca/root2/cps.pdf0,<br/>http://recherche.tf1.fr/,<br/>http://si.wikipedia.org/,<br/>http://list.taobao.com/browse/search_visual.htm?n=15,<br/>http://www.registradores.org/scr/normativa/cp_f2.htm0,<br/>http://crl.microsoft.com/pki/crl/products/TrustListPCA.crl0O,<br/>http://www.usertrust.com1604,<br/>http://search.centrum.cz/,<br/>http://www.auction.co.kr/auction.ico,<br/>http://www.paginasamarillas.es/favicon.ico,<br/>http://ja.wikipedia.org/favicon.ico,<br/>http://www.abril.com.br/favicon.ico,<br/>http://clients5.google.com/complete/search?hl=,<br/>http://www.ozon.ru/,<br/>http://search.alice.it/,<br/>http://www.ssc.lt/cps03,<br/>http://www.microsoft.com/windowsxp/expertzone/,<br/>http://search.yahoo.co.jp/favicon.ico,<br/>http://cnet.search.com/,<br/>http://www.walmart.com/,<br/>http://www.microsoft.com/pki/certs/TrustListPCA.crt0,<br/>http://espn.go.com/favicon.ico,<br/>http://www.pkioverheid.nl/policies/root-policy0,<br/>http://www.mtv.com/favicon.ico,<br/>http://msdn.microsoft.com/workshop/security/szone/overview/templates.asp),<br/>http://search.interpark.com/,<br/>http://www.gmarket.co.kr/favicon.ico,<br/>http://www.certplus.com/CRL/class3.crl0,<br/>http://www.neckermann.de/favicon.ico,<br/>http://sitesearch.timesonline.co.uk/,<br/>http://cn.bing.com/search?q=,<br/>http://video.globo.com/favicon.ico,<br/>http://www.passport.com,<br/>http://es.wikipedia.org/,<br/>http://img.atlas.cz/favicon.ico,<br/>https://www.catcert.net/verarrel,<br/>http://searchresults.news.com.au/,<br/>http://search.rediff.com/,<br/>http://search.lycos.co.uk/,<br/>http://en.wikipedia.org/,<br/>http://www.google.com.tw/,<br/>http://www.tchibo.de/,<br/>http://www.google.com/,<br/>http://buscador.terra.es/,<br/>http://pki-root.ecertpki.cl/CertEnroll/E-CERT%20ROOT%20CA.crl0,<br/>http://crl.ssc.lt/root-a/cacrl.crl0,<br/>http://search.msn.co.jp/results.aspx?q=,<br/>http://www.mercadolivre.com.br/favicon.ico,<br/>http://ja.wikipedia.org/,<br/>http://search.chol.com/,<br/>http://crl.usertrust.com/UTN-USERFirst-Object.crl0),<br/>http://search.espn.go.com/,<br/>http://www.google.com.sa/,<br/>http://jobsearch.monster.com/,<br/>http://buscador.terra.com/,<br/>http://www.google.co.in/,<br/>http://suche.freenet.de/,<br/>http://www.pki.admin.ch/policy/CPS_2_16_756_1_17_3_21_1.pdf0,<br/>http://www.cdiscount.com/favicon.ico,<br/>http://asp.usatoday.com/,<br/>http://vachercher.lycos.fr/,<br/>http://www.yam.com/favicon.ico,<br/>http://search.sify.com/,<br/>http://acraiz.icpbrasil.gov.br/LCRacraiz.crl0,<br/>http://search.ebay.com/favicon.ico,<br/>http://www.paginasamarillas.es/,<br/>http://nl.wikipedia.org/,<br/>http://search.alice.it/favicon.ico,<br/>http://www.ask.com/,<br/>http://www.so-net.ne.jp/share/favicon.ico,<br/>http://espanol.search.yahoo.com/,<br/>http://crl.usertrust.com/UTN-USERFirst-ClientAuthenticationandEmail.crl0,<br/>http://www.alarabiya.net/favicon.ico,<br/>http://pt.wikipedia.org/favicon.ico,<br/>http://ocnsearch.goo.ne.jp/,<br/>http://list.taobao.com/,<br/>http://certificates.starfieldtech.com/repository/1604,<br/>http://buscador.terra.com.br/,<br/>http://search.msn.co.uk/results.aspx?q=,<br/>http://www.google.de/,<br/>http://www.tiscali.it/favicon.ico,<br/>http://search.naver.com/,<br/>http://ie8.ebay.com/open-search/output-xml.php?q=,<br/>http://www.rambler.ru/,<br/>http://esearch.rakuten.co.jp/,<br/>http://www.pki.gva.es/cps0,<br/>http://www.cdiscount.com/,<br/>http://www.mercadolivre.com.br/,<br/>http://www.facebook.com/favicon.ico,<br/>http://www.t-online.de/favicon.ico,<br/>http://search.hanafos.com/,<br/>http://sads.myspace.com/,<br/>http://repository.swisssign.com/0,<br/>http://www.acabogacia.org0,<br/>http://crl.ssc.lt/root-c/cacrl.crl0,<br/>http://suche.web.de/,<br/>http://recherche.tf1.fr/favicon.ico,<br/>http://cs.wikipedia.org/w/api.php?action=opensearch,<br/>http://search.dreamwiz.com/,<br/>http://xml-us.amznxslt.com/onca/xml?Service=AWSECommerceService,<br/>http://www.yandex.ru/,<br/>http://www.e-szigno.hu/RootCA.crl,<br/>http://fedir.comsign.co.il/crl/ComSignAdvancedSecurityCA.crl0,<br/>http://www.trustdst.com/certificates/policy/ACES-index.html0,<br/>http://www.baidu.com/favicon.ico,<br/>http://ariadna.elmundo.es/,<br/>http://www.rtl.de/,<br/>http://www.kkbox.com.tw/favicon.ico,<br/>http://p.zhongsou.com/,<br/>http://www.ancert.com/cps0,<br/>https://ca.sia.it/secsrv/repository/CPS0,<br/>http://www.timesonline.co.uk/img/favicon.ico,<br/>http://buscar.ozu.es/,<br/>http://so-net.search.goo.ne.jp/,<br/>http://cgi.search.biglobe.ne.jp/favicon.ico,<br/>http://search.livedoor.com/,<br/>http://www.soso.com/,<br/>http://www.afisha.ru/App_Themes/Default/images/favicon.ico,<br/>http://img.shopzilla.com/shopzilla/shopzilla.ico,<br/>http://wellformedweb.org/CommentAPI/,<br/>http://crl.oces.certifikat.dk/oces.crl0,<br/>http://ca.sia.it/seccli/repository/CRL.der0J,<br/>http://search.orange.co.uk/,<br/>http://www.myspace.com/favicon.ico,<br/>http://ariadna.elmundo.es/favicon.ico,<br/>http://www.e-szigno.hu/RootCA.crt0,<br/>http://search.gismeteo.ru/,<br/>http://www3.fnac.com/favicon.ico,<br/>http://en.wikipedia.org/w/api.php?action=opensearch,<br/>http://repository.infonotary.com/cps/qcps.html0,<br/>http://ocsp.pki.gva.es0,<br/>http://support.microsoft.com,<br/>http://in.search.yahoo.com/,<br/>http://www.etmall.com.tw/favicon.ico,<br/>http://www.ceneo.pl/favicon.ico,<br/>http://service2.bfast.com/,<br/>http://tw.search.yahoo.com/,<br/>http://es.ask.com/,<br/>http://www.ozu.es/favicon.ico,<br/>http://www.iask.com/favicon.ico,<br/>http://www.dailymail.co.uk/favicon.ico,<br/>http://google.pchome.com.tw/,<br/>http://crl.ssc.lt/root-b/cacrl.crl0,<br/>http://p.zhongsou.com/favicon.ico,<br/>http://crl.securetrust.com/STCA.crl0,<br/>http://acraiz.icpbrasil.gov.br/DPCacraiz.pdf0=,<br/>http://search.ebay.com/,<br/>http://br.search.yahoo.com/,<br/>http://suche.lycos.de/,<br/>http://users.ocsp.d-trust.net03,<br/>http://www.asharqalawsat.com/favicon.ico,<br/>http://mail.live.com/,<br/>http://ru.search.yahoo.com,<br/>http://de.wikipedia.org/,<br/>http://crl.comodo.net/AAACertificateServices.crl0,<br/>http://ns.adobe.com/xap/1.0/mm/,<br/>http://cps.chambersign.org/cps/chambersroot.html0,<br/>http://www.google.ru/,<br/>http://search.empas.com/favicon.ico,<br/>http://search.seznam.cz/,<br/>http://de.wikipedia.org/w/api.php?action=opensearch,<br/>http://www.expedia.com/,<br/>http://www.clarin.com/favicon.ico,<br/>http://www.acabogacia.org/doc0,<br/>http://busca.uol.com.br/,<br/>http://www.sk.ee/cps/0,<br/>http://mail.live.com/?rru=compose%3Fsubject%3D,<br/>https://www.catcert.net/verarrel05,<br/>http://www.certificadodigital.com.br/repositorio/serasaca/crl/SerasaCAI.crl0,<br/>http://crl.securetrust.com/SGCA.crl0,<br/>http://buscador.terra.com/favicon.ico,<br/>http://www.certificadodigital.com.br/repositorio/serasaca/crl/SerasaCAIII.crl0,<br/>http://crl.globalsign.net/root-r2.crl0,<br/>http://purl.org/rss/1.0/modules/slash/,<br/>http://www.d-trust.net0,<br/>http://es.search.yahoo.com/,<br/>http://www.ocn.ne.jp/favicon.ico,<br/>http://www.d-trust.net/crl/d-trust_root_class_2_ca_2007.crl0,<br/>http://corp.naukri.com/,<br/>http://www.amazon.com/exec/obidos/external-search/104-2981279-3455918?index=blended,<br/>http://www.microsofttranslator.com/BV.aspx?ref=IE8Activity,<br/>http://www.recherche.aol.fr/,<br/>http://pl.wikipedia.org/w/api.php?action=opensearch,<br/>http://www.weather.com/favicon.ico,<br/>http://search.centrum.cz/favicon.ico,<br/>http://search.yam.com/,<br/>http://uk.search.yahoo.com/,<br/>http://busca.uol.com.br/favicon.ico,<br/>http://es.wikipedia.org/favicon.ico,<br/>http://images.joins.com/ui_c/fvc_joins.ico,<br/>http://cgi.search.biglobe.ne.jp/,<br/>http://www.microsoft.com/pki/crl/products/TrustListPCA.crl,<br/>http://msk.afisha.ru/,<br/>http://es.wikipedia.org/w/api.php?action=opensearch,<br/>http://www.globaltrust.info0,<br/>http://www.google.pl/,<br/>http://www.arrakis.com/favicon.ico,<br/>http://search.microsoft.com/,<br/>http://search.goo.ne.jp/favicon.ico,<br/>http://image.excite.co.jp/jp/favicon/lep.ico,<br/>https://secure.a-cert.at/cgi-bin/a-cert-advanced.cgi0,<br/>http://www.merlin.com.pl/,<br/>http://crl.usertrust.com/UTN-USERFirst-Hardware.crl01,<br/>http://www.amazon.de/,<br/>http://www.sogou.com/,<br/>http://www.digsigtrust.com/DST_TRUST_CPS_v990701.html0,<br/>http://cerca.lycos.it/,<br/>http://www.usertrust.com1,<br/>http://www.orange.fr/,<br/>http://spaces.live.com/BlogIt.aspx,<br/>http://www.microsofttranslator.com/?ref=IE8Activity,<br/>http://www.rakuten.co.jp/favicon.ico,<br/>http://search.nate.com/,<br/>http://www.nate.com/favicon.ico,<br/>http://de.wikipedia.org/favicon.ico,<br/>http://www.dnie.es/dpc0,<br/>http://www.najdi.si/,<br/>http://www.microsofttranslator.com/DefaultPrev.aspx?ref=IE8Activity,<br/>http://search.daum.net/favicon.ico,<br/>https://www.certification.tn/cgi-bin/pub/crl/cacrl.crl0E,<br/>http://nl.wikipedia.org/favicon.ico,<br/>http://crl.pki.wellsfargo.com/wsprca.crl0,<br/>http://it.search.yahoo.com/,<br/>http://www.google.it/,<br/>http://www.d-trust.net/crl/d-trust_root_class_3_ca_2007.crl0,<br/>http://suche.web.de/favicon.ico,<br/>http://search.seznam.cz/favicon.ico,<br/>http://purl.org/rss/1.0/,<br/>http://search.lycos.com/,<br/>http://fr.wikipedia.org/w/api.php?action=opensearch,<br/>http://qual.ocsp.d-trust.net0,<br/>http://search.dreamwiz.com/favicon.ico,<br/>http://www.kkbox.com.tw/,<br/>http://suche.aol.de/,<br/>http://www.entrust.net/CRL/net1.crl0,<br/>http://www.entrust.net/CRL/Client1.crl0,<br/>http://crl.xrampsecurity.com/XGCA.crl0,<br/>http://search.empas.com/,<br/>http://yellowpages.superpages.com/favicon.ico,<br/>http://arianna.libero.it/,<br/>http://www.dailymail.co.uk/,<br/>http://ru.wikipedia.org/favicon.ico,<br/>http://purl.org/rss/1.0/modules/content/,<br/>http://search.auction.co.kr/,<br/>http://www.certplus.com/CRL/class1.crl0,<br/>http://ocsp.infonotary.com/responder.cgi0V,<br/>http://search.yahoo.co.jp,<br/>http://asp.usatoday.com/favicon.ico,<br/>http://www.signatur.rtr.at/current.crl0,<br/>http://search.msn.com.cn/results.aspx?q=,<br/>http://crl.microsoft.com/pki/crl/products/tspca.crl0H,<br/>http://www.a-cert.at/certificate-policy.html0,<br/>https://localhost,<br/>http://cn.bing.com/favicon.ico,<br/>http://www.firmaprofesional.com0,<br/>http://search2.estadao.com.br/,<br/>http://www.microsoft.com/pki/certs/tspca.crt0,<br/>http://search.cn.yahoo.com/,<br/>http://www.rootca.or.kr/rca/cps.html0,<br/>http://ie.search.yahoo.com/os?command=,<br/>http://www.tesco.com/,<br/>http://search-dyn.tiscali.it/,<br/>http://www.trustcenter.de/crl/v2/tc_class_3_ca_II.crl,<br/>http://search.ipop.co.kr/favicon.ico,<br/>http://arianna.libero.it/favicon.ico,<br/>http://www.sk.ee/juur/crl/0,<br/>http://it.wikipedia.org/,<br/>http://crl.comodo.net/TrustedCertificateServices.crl0,<br/>http://busca.orange.es/,<br/>http://www.microsoft.com/schemas/rss/core/2005/internal,<br/>http://www.baidu.com/,<br/>http://home.altervista.org/,<br/>http://it.search.dada.net/favicon.ico,<br/>http://www.gmarket.co.kr/,<br/>http://www.e-certchile.cl/html/productos/download/CPSv1.7.pdf01,<br/>http://www.informatik.admin.ch/PKI/links/CPS_2_16_756_1_17_3_1_0.pdf0,<br/>http://www.google.com.br/,<br/>http://buscar.ya.com/,<br/>http://images.monster.com/favicon.ico,<br/>http://search.ebay.it/,<br/>http://www.alarabiya.net/,<br/>http://ru.wikipedia.org/w/api.php?action=opensearch,<br/>https://www.certification.tn/cgi-bin/pub/crl/cacrl.crl0,<br/>http://www.maktoob.com/favicon.ico,<br/>http://price.ru/favicon.ico,<br/>http://ns.adobe.com/pdf/1.3/,<br/>http://www.microsoft.com/schemas/ie8tldlistdescription/1.0,<br/>http://logo.verisign.com/vslogo.gif0,<br/>http://price.ru/,<br/>http://www.disig.sk/ca/crl/ca_disig.crl0,<br/>http://www.najdi.si/favicon.ico,<br/>http://kr.search.yahoo.com/,<br/>http://www.aol.com/favicon.ico,<br/>http://www.ozon.ru/favicon.ico,<br/>http://pl.wikipedia.org/,<br/>http://www.target.com/favicon.ico,<br/>http://fr.search.yahoo.com/,<br/>http://crl.usertrust.com/UTN-DATACorpSGC.crl0,<br/>http://search.daum.net/,<br/>http://www.certicamara.com/certicamaraca.crl0,<br/>http://de.search.yahoo.com/,<br/>http://suche.freenet.de/favicon.ico,<br/>http://www.post.trust.ie/reposit/cps.html0,<br/>http://busca.buscape.com.br/favicon.ico,<br/>http://www2.public-trust.com/crl/ct/ctroot.crl0,<br/>http://www.microsoft.com/favicon.ico,<br/>http://www.certicamara.com0,<br/>http://auone.jp/favicon.ico,<br/>http://buscador.lycos.es/,<br/>http://search.yahoo.com/,<br/>http://msdn.microsoft.com/workshop/security/privacy/overview/privacyimportxml.asp),<br/>http://search.rediff.com/favicon.ico,<br/>http://si.wikipedia.org/favicon.ico,<br/>http://www3.fnac.com/,<br/>http://web.ask.com/,<br/>http://ca.sia.it/secsrv/repository/CRL.der0J,<br/>http://search.books.com.tw/,<br/>http://search.ebay.in/,<br/>http://search.about.com/,<br/>http://www.neckermann.de/,<br/>http://www.disig.sk/ca0f,<br/>http://browse.guardian.co.uk/favicon.ico,<br/>http://www.tesco.com/favicon.ico,<br/>http://search.ipop.co.kr/,<br/>https://www.example.com.,<br/>http://www.target.com/,<br/>http://www.amazon.com/favicon.ico,<br/>http://recherche.linternaute.com/,<br/>http://www.google.fr/,<br/>http://www.certicamara.com/dpc/0Z,<br/>http://openimage.interpark.com/interpark.ico,<br/>http://www.google.si/,<br/>http://www.yandex.ru/favicon.ico,<br/>http://www.google.com/favicon.ico,<br/>http://www.walmart.com/favicon.ico,<br/>http://udn.com/,<br/>http://purl.org/dc/elements/1.1/,<br/>http://www.wellsfargo.com/certpolicy0,<br/>http://fedir.comsign.co.il/crl/ComSignCA.crl0,<br/>http://www.google.es/,<br/>http://www.cnet.co.uk/,<br/>http://www.mtv.com/,<br/>http://search.live.com/results.aspx?FORM=IEFM1,<br/>http://www.abril.com.br/,<br/>https://www.netlock.hu/docs/,<br/>http://search1.taobao.com/,<br/>http://www.a-cert.at0E,<br/>http://www.amazon.co.uk/,<br/>http://it.wikipedia.org/w/api.php?action=opensearch,<br/>http://www.tchibo.de/favicon.ico,<br/>http://www.pchome.com.tw/favicon.ico,<br/>http://pt.wikipedia.org/,<br/>http://fr.wikipedia.org/,<br/>http://crl.netsolssl.com/NetworkSolutionsCertificateAuthority.crl0,<br/>https://rca.e-szigno.hu/ocsp0-,<br/>http://ja.wikipedia.org/w/api.php?action=opensearch,<br/>https://ca.sia.it/seccli/repository/CPS0,<br/>http://www.chennaionline.com/ncommon/images/collogo.ico,<br/>http://www.cjmall.com/,<br/>http://search.live.com/results.aspx?q=,<br/>http://www.comsign.co.il/cps0,<br/>http://www.certifikat.dk/repository0,<br/>http://cps.chambersign.org/cps/publicnotaryroot.html0,<br/>http://search.yahoo.com/favicon.ico,<br/>http://www.quovadisglobal.com/cps0,<br/>http://busca.igbusca.com.br/,<br/>http://ca.disig.sk/ca/crl/ca_disig.crl0,<br/>http://www.nifty.com/favicon.ico,<br/>http://cps.chambersign.org/cps/chambersignroot.html0,<br/>http://www.sify.com/favicon.ico,<br/>http://www.certplus.com/CRL/class2.crl0,<br/>http://home.altervista.org/favicon.ico,<br/>http://search.gamer.com.tw/favicon.ico,<br/>http://busca.buscape.com.br/,<br/>http://search.atlas.cz/,<br/>http://www.ceneo.pl/,<br/>http://crl.chambersign.org/chambersignroot.crl0,<br/>http://www.certplus.com/CRL/class3P.crl0,<br/>https://www.netlock.net/docs,<br/>http://pl.wikipedia.org/favicon.ico,<br/>http://ns.adobe.com/iX/1.0/,<br/>http://search.books.com.tw/favicon.ico,<br/>http://search.aol.in/,<br/>http://crl.comodoca.com/TrustedCertificateServices.crl0:,<br/>https://example.com,<br/>http://cs.wikipedia.org/favicon.ico,<br/>http://spaces.live.com/,<br/>http://www.valicert.com/1,<br/>http://crl.comodoca.com/AAACertificateServices.crl06,<br/>http://www.microsofttranslator.com/Default.aspx?ref=IE8Activity,<br/>http://www.crc.bg0,<br/>http://z.about.com/m/a08.ico,<br/>http://www.univision.com/favicon.ico,<br/>http://crl.comodoca.com/COMODOCertificationAuthority.crl0,<br/>http://nl.wikipedia.org/w/api.php?action=opensearch,<br/>http://search.aol.co.uk/<br/>host: 25.20.116.113,<br/>103.143.173.25<br/>path: {"pdb_path": [], "filepaths": {"file_read": ["C:\\Users\\desktop.ini", "C:\\Users\\Administrator\\Documents\\desktop.ini"], "dll_loaded": ["kernel32", "gdi32.dll", "kernel32.dll", "UxTheme.dll", "oleaut32.dll", "C:\\Windows\\system32\\ole32.dll", "NTDLL.DLL", "dwmapi.dll", "ntdll.dll", "C:\\Windows\\WinSxS\\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.17514_none_72d18a4386696c80\\gdiplus.dll", "USER32.DLL", "C:\\Windows\\system32\\uxtheme.dll", "ntmarta.dll", "C:\\Windows\\system32\\MSCTF.dll", "KERNEL32.DLL", "C:\\ogxses\\bin\\monitor-x86.dll", "KERNELBASE.DLL", "API-MS-Win-Core-LocalRegistry-L1-1-0.dll", "user32", "OLEAUT32.DLL", "advapi32.dll", "comctl32", "ole32.dll", "IMM32.dll", "C:\\Windows\\system32\\notepad.exe", "EXPLORER.EXE", "C:\\Windows\\system32\\xmllite.dll", "OLEAUT32.dll", "SHELL32.dll", "DUser.dll", "comctl32.dll", "C:\\Windows\\system32\\DUser.dll", "User32.dll", "USER32", "ADVAPI32.dll", "rpcrt4.dll", "SETUPAPI.dll", "user32.dll", "OLEACC.dll"], "file_moved": [], "file_copied": ["C:\\Users\\Administrator\\Documents\\MSDCSC\\msdcsc.exe", "C:\\Users\\Administrator\\AppData\\Local\\Temp\\sXPFvH.exe"], "file_exists": ["C:\\Windows\\System32\\oleaccrc.dll", "C:\\Users\\Administrator\\Documents\\MSDCSC", "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches\\cversions.1.db", "C:\\", "C:\\Users\\Administrator\\AppData\\Roaming", "C:\\Users\\desktop.ini", "C:\\Users\\Administrator\\Documents\\MSDCSC\\", "C:\\Users\\Administrator\\Documents\\MSDCSC\\rEj9MRKQ3Kzp\\msdcsc.exe", "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches\\{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000026.db", "C:\\Users\\Administrator\\AppData\\Local\\Temp\\sXPFvH.exe", "C:\\Users\\Administrator\\Documents\\MSDCSC\\rEj9MRKQ3Kzp.dcp", "C:\\Users\\Administrator", "C:\\Users\\Administrator\\Documents", "C:\\Users", "C:\\Users\\Administrator\\AppData\\Local\\Temp\\notepad", "C:\\Users\\Administrator\\AppData\\Roaming\\dclogs\\", "C:\\Users\\Administrator\\Documents\\desktop.ini", "C:\\Users\\Administrator\\Documents\\MSDCSC\\msdcsc.exe", "C:\\Users\\Administrator\\AppData\\Local\\Temp\\rEj9MRKQ3Kzp.dcp", "C:\\Users\\Administrator\\AppData\\Roaming\\dclogs"], "file_opened": ["C:\\Windows\\System32\\oleaccrc.dll", "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches\\cversions.1.db", "C:\\", "C:\\Users\\desktop.ini", "C:\\Users\\Administrator\\Documents\\desktop.ini", "C:\\Users\\Administrator", "C:\\Users", "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches\\{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000026.db", "C:\\Users\\Administrator\\Documents\\MSDCSC\\msdcsc.exe", "C:\\Users\\Administrator\\AppData\\Local\\Temp\\sXPFvH.exe"], "file_created": ["C:\\Windows\\System32\\oleaccrc.dll", "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches\\cversions.1.db", "C:\\", "C:\\Users\\desktop.ini", "C:\\Users\\Administrator\\Documents\\desktop.ini", "C:\\Users\\Administrator", "C:\\Users", "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches\\{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000026.db", "C:\\Users\\Administrator\\Documents\\MSDCSC\\msdcsc.exe", "C:\\Users\\Administrator\\AppData\\Local\\Temp\\sXPFvH.exe"], "file_deleted": [], "file_written": [], "directory_created": ["C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches", "C:\\Users\\Administrator\\Documents\\MSDCSC", "C:\\Users\\Administrator\\AppData\\Roaming\\dclogs"], "directory_queried": ["C:\\Users\\Administrator", "C:\\Users\\Administrator\\Documents", "C:\\Users"], "directory_removed": [], "directory_enumerated": []}}<br/>yara: {"url": [], "misc": {"misc": ["dbgdetect_funcs_ig"], "crypto": ["RIPEMD160_Constants", "SHA1_Constants", "DES_Long", "MD5_Constants", "VC8_Random", "RijnDael_AES_LONG", "Delphi_Random", "BASE64_table", "CRC32_table", "RijnDael_AES_CHAR", "MD5_API"], "packer": ["MinGW_1", "borland_delphi"]}, "memory": ["darkcomet_memory_1", "darkcomet_memory_3", "darkcomet_memory_2", "darkcomet_memory_4"], "generic": [], "pre_analysis": []}<br/>email: <br/>mutex: DCPERSFWBP,<br/>DC_MUTEX-K5CAEA3,<br/>Local\MSCTF.Asm.MutexDefault1<br/>ports: {"tcp": [], "udp": [], "tcp_dead": [80, 957]}<br/>domain: <br/>regkeys: {"regkey_read": ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient\\Windows\\DisabledProcesses\\21082CA9", "HKEY_CURRENT_USER\\Keyboard Layout\\Toggle\\Language Hotkey", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Rpc\\MaxRpcSize", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\UseDropHandler", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{0000897b-83df-4b96-be07-0fb58b01c4a4}\\LanguageProfile\\0x00000000\\{0001bea3-ed56-483d-a2e2-aeae25577436}\\Enable", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfOutPrecision", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\WantsFORPARSING", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\StatusBar", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoNetCrawling", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\NoNetCrawling", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfOrientation", "HKEY_LOCAL_MACHINE\\SYSTEM\\Setup\\SystemSetupInProgress", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfUnderline", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DontShowSuperHidden", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Filter", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\QueryForOverlay", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Notepad\\DefaultFonts\\iPointSize", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\SourcePath", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\NoFileFolderJunction", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\services\\ldap\\UseOldHostResolutionOrder", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Folder\\NeverShowExt", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowInfoTip", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\WantsParseDisplayName", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\IDConfigDB\\CurrentConfig", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\iMarginTop", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideIcons", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\fSaveWindowPositions", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\WantsAliasedNotifications", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\iMarginBottom", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\iMarginLeft", "HKEY_CURRENT_USER\\Software\\DC3_FEXEC\\{e29ac6c0-7037-11de-816d-806e6f6e6963-4234460882}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\NonEnum\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\AlwaysShowExt", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\IDConfigDB\\CurrentDockInfo\\DockingState", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\IDConfigDB\\Hardware Profiles\\0001\\HwProfileGuid", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes\\Segoe UI", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Interface\\{618736E0-3C3D-11CF-810C-00AA00389B71}\\ProxyStubClsid32\\(Default)", "HKEY_CURRENT_USER\\Keyboard Layout\\Toggle\\Layout Hotkey", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfClipPrecision", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\RestrictedAttributes", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoSimpleStartMenu", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AllFilesystemObjects\\IsShortcut", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Notepad\\DefaultFonts\\lfFaceName", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AllFilesystemObjects\\BrowseInPlace", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfCharSet", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\IconsOnly", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\HideOnDesktopPerUser", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AllFilesystemObjects\\DocObject", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient\\Windows\\DisabledSessions\\MachineThrottling", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume\\{0ad25834-bdda-11e5-8e00-806e6f6e6963}\\Generation", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\AutoCheckSelect", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\CallForAttributes", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume\\{0ad25835-bdda-11e5-8e00-806e6f6e6963}\\Generation", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\HideInWebView", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\SeparateProcess", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\BrowseInPlace", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\SeparateProcess", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\fMLE_is_broken", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\WantsFORDISPLAY", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfFaceName", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Folder\\DocObject", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfItalic", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DevicePath", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\WebView", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\QueryForInfoTip", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfWeight", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\IDConfigDB\\Hardware Profiles\\0001\\FriendlyName", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowCompColor", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\ClassicShell", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoWebView", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfStrikeOut", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes\\MS Shell Dlg 2", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\Attributes", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\MapNetDrvBtn", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfPitchAndFamily", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\IsShortcut", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\iPointSize", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa\\AccessProviders\\MartaExtension", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\DontPrettyPath", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\iMarginRight", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfQuality", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\szTrailer", "HKEY_LOCAL_MACHINE\\SYSTEM\\Setup\\OOBEInProgress", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\PinToNameSpaceTree", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\HasNavigationEnum", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\iWindowPosX", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\iWindowPosY", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume\\{0ad25835-bdda-11e5-8e00-806e6f6e6963}\\Data", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\fWrap", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellState", "HKEY_CURRENT_USER\\Keyboard Layout\\Toggle\\Hotkey", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume\\{0ad25838-bdda-11e5-8e00-806e6f6e6963}\\Data", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowTypeOverlay", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Nls\\ExtendedLocale\\es-ES", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\services\\ldap\\LdapClientIntegrity", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume\\{0ad25834-bdda-11e5-8e00-806e6f6e6963}\\Data", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\HideFolderVerbs", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\NeverShowExt", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize\\DisableMetaFiles", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Drive\\shellex\\FolderExtensions\\{fbeb8a05-beee-4442-804e-409d6c4515e9}\\DriveMask", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\MapNetDriveVerbs", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient\\Windows\\DisabledSessions\\GlobalSession", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\DocObject", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AllFilesystemObjects\\NeverShowExt", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Nls\\CustomLocale\\es-ES", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Folder\\IsShortcut", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient\\Windows\\CEIPEnable", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\szHeader", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\services\\ldap\\UseHostnameAsAlias", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ActiveComputerName\\ComputerName", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\iWindowPosDY", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\iWindowPosDX", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume\\{0ad25838-bdda-11e5-8e00-806e6f6e6963}\\Generation", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\EnableAnchorContext", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\TurnOffSPIAnimations", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad\\lfEscapement", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Folder\\BrowseInPlace", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder\\WantsUniversalDelegate"], "regkey_opened": ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{8613E14C-D0C0-4161-AC0F-1DD2563286BC}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_CURRENT_USER\\Software\\DC2_USERS", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SQMClient\\Windows\\DisabledProcesses\\", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{0000897b-83df-4b96-be07-0fb58b01c4a4}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\CTF\\TIP\\{0000897b-83df-4b96-be07-0fb58b01c4a4}\\LanguageProfile\\0x00000000\\{0001bea3-ed56-483d-a2e2-aeae25577436}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\KnownClasses", "HKEY_CLASSES_ROOT\\Folder", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{C1EE01F2-B3B6-4A6A-9DDD-E988C088EC82}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SQMClient\\Windows", "HKEY_CLASSES_ROOT\\Directory", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\", "HKEY_CLASSES_ROOT\\Drive\\shellex\\FolderExtensions", "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\LSA\\AccessProviders", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume", "HKEY_CURRENT_USER\\Software\\Borland\\Locales", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Folder\\ShellEx\\IconHandler", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume\\{0ad25838-bdda-11e5-8e00-806e6f6e6963}\\", "HKEY_CURRENT_USER\\Software\\Microsoft\\CTF\\DirectSwitchHotkeys", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{03B5835F-F03C-411B-9CE2-AA23E1171E36}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\(Default)", "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Explorer", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{FA445657-9379-11D6-B41A-00065B83EE53}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Folder\\Clsid", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Nls\\ExtendedLocale", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\IDConfigDB\\Hardware Profiles\\0001", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{F25E9F57-2FC8-4EB3-A41A-CCE5F08541E6}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "HKEY_CLASSES_ROOT\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder", "HKEY_LOCAL_MACHINE\\System\\Setup", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AllFilesystemObjects\\BrowseInPlace", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\Directory", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{DCBD6FA8-032F-11D3-B5B1-00C04FC324A1}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AllFilesystemObjects\\DocObject", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder", "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Nls\\CustomLocale", "HKEY_CURRENT_USER\\Software\\DC3_FEXEC", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\CurVer", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\BrowseInPlace", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{70FAF614-E0B1-11D3-8F5C-00C04F9CF4AC}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\NonEnum", "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Folder\\DocObject", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\ShellEx\\IconHandler", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Setup", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\Shell\\RegisteredApplications\\UrlAssociations\\Directory\\OpenWithProgids", "HKEY_CLASSES_ROOT\\Drive\\shellex\\FolderExtensions\\{fbeb8a05-beee-4442-804e-409d6c4515e9}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Notepad\\DefaultFonts", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{AE6BE008-07FB-400D-8BEB-337A64F7051F}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_CLASSES_ROOT\\Interface\\{618736E0-3C3D-11CF-810C-00AA00389B71}\\ProxyStubClsid32", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{E429B25A-E5D3-4D1F-9BE3-0C608477E3A1}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{F89E9E58-BD2F-4008-9AC2-0F816C09F4EE}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AllFilesystemObjects\\Clsid", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\DirectUI", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\Clsid", "HKEY_CURRENT_USER\\Keyboard Layout\\Toggle", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SQMClient\\Windows", "HKEY_CURRENT_USER\\Software\\Microsoft\\Notepad", "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LDAP", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes", "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\IDConfigDB", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{78CB5B0E-26ED-4FCC-854C-77E8F3D1AA80}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SQMClient\\Windows\\DisabledSessions\\", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\ShellFolder", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\AllFilesystemObjects\\ShellEx\\IconHandler", "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\IDConfigDB\\CurrentDockInfo", "HKEY_LOCAL_MACHINE\\Software\\Borland\\Locales", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{81D4E9C9-1D3B-41BC-9E6C-4B40BF79E35E}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\NonEnum", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Rpc", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\Compatibility\\notepad.exe", "HKEY_CURRENT_USER\\Software\\Borland\\Delphi\\Locales", "HKEY_CLASSES_ROOT\\AllFilesystemObjects", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume\\{0ad25835-bdda-11e5-8e00-806e6f6e6963}\\", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume\\{0ad25834-bdda-11e5-8e00-806e6f6e6963}\\", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\DocObject", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\(Default)", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{3697C5FA-60DD-4B56-92D4-74A569205C16}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{A028AE76-01B1-46C2-99C4-ACD9858AE02F}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{07EB03D6-B001-41DF-9192-BF9B841EE71F}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Folder\\BrowseInPlace"], "regkey_created": ["HKEY_CURRENT_USER\\Software", "HKEY_CURRENT_USER\\Software\\DC3_FEXEC", "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"], "regkey_deleted": [], "regkey_written": ["HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicroUpdate", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UserInit"], "regkey_enumerated": ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{78CB5B0E-26ED-4FCC-854C-77E8F3D1AA80}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP\\{3697C5FA-60DD-4B56-92D4-74A569205C16}\\Category\\Category\\{534C48C1-0607-4098-A521-4FC899C73E90}", "HKEY_CURRENT_USER\\Software\\Microsoft\\CTF\\DirectSwitchHotkeys"]}<br/>metadata: {"crc32": {"original": "B7CACEE9", "unpacked": {}}, "names": {"title": [], "author": [], "country": [], "creator": [], "subject": [], "locality": [], "producer": [], "common_name": [], "company_name": null, "organization": [], "product_name": null, "internal_name": null, "private_build": null, "special_build": null, "legal_copyright": null, "legal_trademarks": null, "original_filename": null, "organizational_unit": []}, "ssdeep": {"original": "12288:f9HFJ9rJxRX1uVVjoaWSoynxdO1FVBaOiRZTERfIhNkNCCLo9Ek5C/hPA:JZ1xuVVjfFoynPaVBUR8f+kN10EBO", "unpacked": {}}, "file_type": {"original": "PE32 executable (GUI) Intel 80386, for MS Windows", "unpacked": {}}, "pe_imphash": "e5b4359a3773764a372173074ae9b6bd", "postal_code": null, "pe_timestamp": "2012-06-07 17:59:53", "signing_date": "", "peid_signatures": []}<br/>registry: <br/>connections: {"tcp": [], "udp": [], "tcp_dead": ["25.20.116.113:957", "103.143.173.25:80"]}<br/>certificates: <br/>process_name: msdcsc.exe,<br/>sXPFvH.exe,<br/>notepad.exe<br/>attack_patterns: {'id': 'T1022', 'name': 'Data Encrypted'},<br/>{'id': 'T1056', 'name': 'Input Capture'},<br/>{'id': 'T1529', 'name': 'System Shutdown/Reboot'},<br/>{'id': 'T1027', 'name': 'Obfuscated Files or Information'},<br/>{'id': 'T1045', 'name': 'Software Packing'},<br/>{'id': 'T1055', 'name': 'Process Injection'},<br/>{'id': 'T1497', 'name': 'Virtualization/Sandbox Evasion'},<br/>{'id': 'T1115', 'name': 'Clipboard Data'},<br/>{'id': 'T1060', 'name': 'Registry Run Keys / Startup Folder'},<br/>{'id': 'T1093', 'name': 'Process Hollowing'} | https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1/ioc/ | 2020-06-15T16:48:42.527191Z | 2020-06-15T18:25:32Z | self: https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1/ | false | 2 | 36a40cc55e2ffe7d44d007c6e37afd7f | false |  | 0 | https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1/pcap/ | 3 | false |  | https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1/report/ | 7.0 | https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1/sample/ | https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1/enrichment/scans/ | false | 5c0be68316ce77584a7b966ff40e7d61a8a98055 | ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1 | e7ebf12d5dc0900faafa73d090b62c1ce583858606217d935981bf3d51dbd6e63eefd67b103913240173b2bafbcaac689d83828654ecf054cb7a30766c4a3cc6 |  | virustotalAPI | DARKCOMET | false | white | Malware | DARKCOMET | 2020-06-15T17:12:28.893118Z | 2020-06-15T16:30:33.293000Z |  | none | darkkomet,<br/>fynloski,<br/>genmalicious |


### blueliv-tc-indicator-ip
***
Gets information about an IP


#### Base Command

`blueliv-tc-indicator-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| IP_id | Internal Blueliv's IP ID | Required | 
| IP | IP to search | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| indicator.lastSeen | Unknown | Indicator last seen | 
| indicator.risk | Unknown | Indicator risk | 
| indicator.latitude | Unknown | Indicator latitude | 
| indicator.longitude | Unknown | Indicator longitude | 
| indicator.countryId | Unknown | Indicator countryes internal IDs | 
| indicator.campaigns | Unknown | Indicator campaigns | 
| indicator.campaignIds | Unknown | Indicator campaigns internal IDs | 
| indicator.signatures | Unknown | Indicator signatures | 
| indicator.signatureIds | Unknown | Indicator signatures internal IDs | 
| indicator.threatActors | Unknown | Indicator threat actors | 
| indicator.threatActorIds | Unknown | Indicator threat actors internal IDs | 
| indicator.tags | Unknown | Indicator tags | 
| indicator.tagIds | Unknown | Indicator tags internal IDs | 
| indicator.fqdns | Unknown | Indicator FQDNs | 
| indicator.fqdnIds | Unknown | Indicator FQDNs internal IDs | 
| indicator.sparks | Unknown | Indicator sparks | 
| indicator.sparkIds | Unknown | Indicator sparks internal IDs | 
| indicator.bots | Unknown | Indicator bots | 
| indicator.botIds | Unknown | Indicator bots internal IDs | 


#### Command Example
```!blueliv-tc-indicator-ip IP="103.76.228.28"```

#### Context Example
```
{
    "indicator": {
        "botIds": "",
        "bots": 0,
        "campaignIds": "",
        "campaigns": 0,
        "countryId": "103",
        "fqdnIds": "",
        "fqdns": 0,
        "lastSeen": "2020-06-15T18:25:00Z",
        "latitude": "20.0",
        "longitude": "77.0",
        "risk": "4.0",
        "signatureIds": "",
        "signatures": 0,
        "sparkIds": "",
        "sparks": 0,
        "tagIds": "",
        "tags": 0,
        "threatActorIds": "",
        "threatActors": 0
    },
    "threatContext": {
        "hasResults": "true"
    }
}
```

#### Human Readable Output

>### Blueliv IP info
>|address|asn_number|asn_owner|at_afapi|created_at|created_at_afapi|first_seen|history_link|id|ioc_link|last_risk_scoring|last_seen|latitude|links|longitude|passive_dns_link|risk|slugs_tags|tlp|type|updated_at|updated_at_afapi|virus_total_link|whois_link|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 103.76.228.28 | 394695 | PDR | false | 2019-05-03T09:57:46.834135Z |  | 2019-04-11T04:12:09.830000Z | https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/history/ | 70236228 | https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/ioc/ | 2020-06-15T15:17:47.624936Z | 2020-06-15T18:25:00Z | 20.0 | self: https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/ | 77.0 | https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/enrichment/passive-dns/ | 4.0 |  | amber | IP | 2020-06-15T16:44:49.623167Z |  | https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/enrichment/virus-total/ | https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/enrichment/whois/ |


### blueliv-tc-cve
***
Gets information about CVE


#### Base Command

`blueliv-tc-cve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| CVE | CVE to search | Optional | 
| CVE_id | Internal Blueliv's CVE ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| cve.name | Unknown | CVE name | 
| cve.description | Unknown | CVE description | 
| cve.updatedAt | Unknown | CVE updated at | 
| cve.score | Unknown | CVE score | 
| cve.attackPatterns | Unknown | CVE attack patterns | 
| cve.attackPatternIds | Unknown | CVE attackp patterns internal IDs | 
| cve.signatures | Unknown | CVE signatures | 
| cve.signatureIds | Unknown | CVE signatures internal IDs | 
| cve.tags | Unknown | CVE tags | 
| cve.tagIds | Unknown | CVE tags internal IDs | 
| cve.crimeServers | Unknown | CVE Crime servers | 
| cve.crimeServerIds | Unknown | CVE crime servers internal IDs | 
| cve.sparks | Unknown | CVE sparks | 
| cve.sparkIds | Unknown | CVE sparks internal IDs | 
| cve.malware | Unknown | CVE malware | 
| cve.malwareIds | Unknown | CVE malwares internal IDs | 
| cve.exploits | Unknown | CVE exploits | 
| cve.platforms | Unknown | CVE platforms | 


#### Command Example
```!blueliv-tc-cve CVE="CVE-2020-8794"```

#### Context Example
```
{}
```

#### Human Readable Output

>{"apiId": "THIAPP", "url": "/api/v1/cve/CVE-2020-8794/relationships/attack-pattern/", "requestType": "GET"}

### blueliv-tc-indicator-fqdn
***
Gets information about FQDN


#### Base Command

`blueliv-tc-indicator-fqdn`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| FQDN_id | Internal Blueliv's FQDN id | Optional | 
| FQDN | FQDN to search | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| indicator.lastSeen | Unknown | Indicator last seen | 
| indicator.risk | Unknown | Indicator risk | 
| indicator.campaigns | Unknown | Indicator campaigns | 
| indicator.campaignIds | Unknown | Indicator campaigns internal IDs | 
| indicator.signatures | Unknown | Indicator signatures | 
| indicator.signatureIds | Unknown | Indicator signatures internal IDs | 
| indicator.threatActors | Unknown | Indicator threat actors | 
| indicator.threatActorIds | Unknown | Indicator threat actors internal IDs | 
| indicator.tags | Unknown | Indicator tags | 
| indicator.tagIds | Unknown | Indicator tags internal IDs | 
| indicator.crimeServers | Unknown | Indicator crime servers | 
| indicator.crimeServerIds | Unknown | Indicator crime servers internal IDs | 
| indicator.sparks | Unknown | Indicator sparks | 
| indicator.sparkIds | Unknown | Indicator sparks internal IDs | 
| indicator.ips | Unknown | Indicator IPs | 
| indicator.ipIds | Unknown | Indicator IPs internal IDs | 


#### Command Example
```!blueliv-tc-indicator-fqdn FQDN="self-repair.r53-2.services.mozilla.com"```

#### Context Example
```
{
    "indicator": {
        "campaignIds": "",
        "campaigns": 0,
        "crimeServerIds": "",
        "crimeServers": 0,
        "ipIds": "",
        "ips": 0,
        "lastSeen": "2018-08-07T22:40:47.580489Z",
        "risk": "2.5",
        "signatureIds": "",
        "signatures": 0,
        "sparkIds": "",
        "sparks": 0,
        "tagids": "",
        "tags": 0,
        "threatActorIds": "",
        "threatActors": 0
    },
    "threatContext": {
        "hasResults": "true"
    }
}
```

#### Human Readable Output

>### Blueliv FQDN info
>|active_dns_link|created_at|domain|first_seen|history_link|id|ioc_link|last_risk_scoring|last_seen|links|passive_dns_link|risk|slugs_tags|tlp|type|updated_at|virus_total_link|whois_link|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| https://tctrustoylo.blueliv.com/api/v1/fqdn/anad.ir/enrichment/dns/ | 2018-08-07T22:40:47.580640Z | anad.ir | 2018-08-07T22:40:47.580479Z | https://tctrustoylo.blueliv.com/api/v1/fqdn/anad.ir/history/ | 5783871 | https://tctrustoylo.blueliv.com/api/v1/fqdn/anad.ir/ioc/ | 2020-06-15T17:25:37.498738Z | 2018-08-07T22:40:47.580489Z | self: https://tctrustoylo.blueliv.com/api/v1/fqdn/anad.ir/ | https://tctrustoylo.blueliv.com/api/v1/fqdn/anad.ir/enrichment/passive-dns/ | 2.5 |  | white | FQDN | 2020-06-15T17:25:37.499246Z | https://tctrustoylo.blueliv.com/api/v1/fqdn/anad.ir/enrichment/virus-total/ | https://tctrustoylo.blueliv.com/api/v1/fqdn/anad.ir/enrichment/whois/ |


### blueliv-tc-indicator-cs
***
Gets information about a Crime Server


#### Base Command

`blueliv-tc-indicator-cs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| CS_id | Internal Blueliv's Crime Server id | Required | 
| CS | The name of the Crime Server to search | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| indicator.lastSeen | Unknown | Indicator lastSeen | 
| indicator.status | Unknown | Indicator status | 
| indicator.risk | Unknown | Indicator risk | 
| indicator.isFalsePositive | Unknown | Indicator is a false positive | 
| indicator.crimeServerUrl | Unknown | Indicator crime server URL | 
| indicator.creditCardsCount | Unknown | Indicator credit cards count | 
| indicator.credentialsCount | Unknown | Indicator credentials count | 
| indicator.botsCount | Unknown | Indicator bots count | 
| indicator.fqdnId | Unknown | Indicator FQDNs internal IDs | 
| indicator.malware | Unknown | Indicator malware | 
| indicator.malwareIds | Unknown | Indicator malwares internal IDs | 
| indicator.tags | Unknown | Indicator tags | 
| indicator.tagIds | Unknown | Indicator tags internal IDs | 
| indicator.sparks | Unknown | Indicator sparks | 
| indicator.sparkIds | Unknown | Indicator sparks internal IDs | 


#### Command Example
```!blueliv-tc-indicator-cs CS_id=6626263```

#### Context Example
```
{
    "indicator": {
        "botsCount": "0",
        "credentialsCount": "0",
        "creditCardsCount": "0",
        "crimeServerUrl": "http://saveback.xyz/asdfgh35546fhwJYGvdfgsadsg/login.php",
        "fqdnId": "9633658",
        "isFalsePositive": "False",
        "lastSeen": "2020-06-15T16:46:06.170000Z",
        "malware": 0,
        "malwareIds": "",
        "risk": "4.0",
        "sourceIds": "642676,",
        "sources": 1,
        "sparkIds": "",
        "sparks": 0,
        "status": "online",
        "tagIds": "",
        "tags": 0
    },
    "threatContext": {
        "hasResults": "true"
    }
}
```

#### Human Readable Output

>### Blueliv Crime Server info
>|at_feed|at_free_feed|bots_count|confidence|created_at|created_at_afapi|credentials_count|credit_cards_count|crime_server_url|false_positive_modification_time|first_seen|id|ioc_link|is_false_positive|last_log_timestamp|last_risk_scoring|last_seen|links|main_type|risk|scans_link|service_scans|slugs_tags|status|subtype_name|target_status|tlp|type|updated_at|updated_at_afapi|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | true | 0 | 1 | 2020-06-15T17:02:40.327300Z | 2020-06-15T16:46:06.119000Z | 0 | 0 | http://saveback.xyz/asdfgh35546fhwJYGvdfgsadsg/login.php | 2020-06-15T17:02:38.524874Z | 2020-06-15T16:44:25Z | 6626263 | https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/ioc/ | false |  | 2020-06-15T17:14:36.146566Z | 2020-06-15T16:46:06.170000Z | self: https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/ | c_and_c | 4.0 | https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/enrichment/scans/ |  |  | online | ANUBIS |  | amber | CrimeServer | 2020-06-15T17:14:36.149943Z | 2020-06-15T16:46:06.170000Z |


### blueliv-tc-threat-actor
***
Gets information about a Threat Actor


#### Base Command

`blueliv-tc-threat-actor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threatActor | Threat Actor to search | Optional | 
| threatActor_id | Internal Blueliv's Threat Actor id | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| threatActor.name | Unknown | Threat actor name | 
| threatActor.description | Unknown | Threat actor description | 
| threatActor.objective | Unknown | Threat actor objective | 
| threatActor.sophistication | Unknown | Threat actor sophistication | 
| threatActor.lastSeen | Unknown | Threat actor last seen | 
| threatActor.active | Unknown | Threat actor active | 
| threatActor.milestones | Unknown | Threat actor milestones | 
| threatActor.milestoneIds | Unknown | Threat actor milestones internal IDs | 
| threatActor.tools | Unknown | Threat actor tools | 
| threatActor.toolIds | Unknown | Threat actor tools internal IDs | 
| threatActor.campaigns | Unknown | Threat actor campaigns | 
| threatActor.campaignIds | Unknown | Threat actor campaigns internal IDs | 
| threatActor.signatures | Unknown | Threat actor signatures | 
| threatActor.signatureIds | Unknown | Threat actor signatures internal IDs | 
| threatActor.onlineServices | Unknown | Threat actor online services | 
| threatActor.onlineServiceIds | Unknown | Threat actor online services internal IDs | 
| threatActor.malware | Unknown | Threat actor malware | 
| threatActor.malwareIds | Unknown | Threat actor malwares internal IDs | 
| threatActor.threatTypes | Unknown | Threat actor threat types | 
| threatActor.threatTypeIds | Unknown | Threat actor threat types internal IDs | 
| threatActor.fqdns | Unknown | Threat actor FQDNs | 
| threatActor.fqdnIds | Unknown | Threat actor FQDNs internal IDs | 
| threatActor.attackPatterns | Unknown | Threat actor attack patterns | 
| threatActor.attackPatternIds | Unknown | Threat actor attack patterns internal IDs | 
| threatActor.ips | Unknown | Threat actor IPs | 
| threatActor.ipIds | Unknown | Threat actor IPs internal IDs | 
| threatActor.targets | Unknown | Threat actor targets | 
| threatActor.targetIds | Unknown | Threat actor targets internal IDs | 


#### Command Example
```!blueliv-tc-threat-actor threatActor=Vendetta```

#### Context Example
```
{
    "threatAactor": {
        "onlineServices": 0,
        "threatTypes": 0
    },
    "threatActor": {
        "active": "True",
        "attackPatternIds": "511,529,603,613,703,705,735,",
        "attackPatterns": 7,
        "campaignIds": "",
        "campaigns": 0,
        "description": "<h5>Key Points</h5>\n\n<ul>\n\t<li>\n\t<p>Vendetta is a threat actor based on Italy or Turkey discovered in April 2020&nbsp;that seeks to steal targeted business intelligence.</p>\n\t</li>\n\t<li>\n\t<p>Vendetta targeted enterprises located in North America, Eastern Europe, Asia, and Oceania regions.</p>\n\t</li>\n\t<li>The threat actor uses social engineering techniques to infect the victims with a RAT.</li>\n</ul>\n\n<h5>Assessment</h5>\n\n<p>Vendetta is a Threat Actor that became active on April 2020, and was discovered by&nbsp;360 Baize Lab. The name comes from a PDB path found in one of the samples:</p>\n\n<div style=\"background:#eeeeee; border:1px solid #cccccc; padding:5px 10px\">C:\\Users\\<strong>Vendetta</strong>\\source\\repos\\{project name}\\*\\obj\\Debug\\{project name}.pdb</div>\n\n<p>Based on some information found on the samples themselves, and the tools used, 360 Baize Labs speculates that the actor is of European origin, either from Turkey or from Italy. Some of their malware samples contain the text &quot;Developers from Italy&quot; which indicates the threat actor may be Italian, but these also contain&nbsp;Turkish names in variables&nbsp;like RoboSky suggest they could actually be from Turkey.</p>\n\n<p>Vendetta targeted its victims with highly convincing spearphishing emails, impersonating entities such as&nbsp;Australian Government Department of Health,&nbsp;Austrian Federal Ministry of the Interior (BMI), or the&nbsp;Mexican health department. The emails contained a malicious attachment called pdf.exe,&nbsp;trying to trick the victim into opening the executable file thinking it is a pdf file, which ultimately installed the <a href=\"https://thiapp2.blueliv.net/#/ui/intelligence/tools/details/136\">NanoCore</a> and <a href=\"https://thiapp2.blueliv.net/#/ui/intelligence/tools/details/193\">RemcosRAT</a> malware.</p>",
        "fqdnIds": "9607329,",
        "fqdns": 1,
        "ips": 1,
        "lastSeen": "2020-06-10T00:00:00Z",
        "malware": 56,
        "malwareIds": "55048892,55954618,56069689,56081184,56101608,56174304,56435633,56482393,56528142,56528442,56660508,56822336,56834251,56895357,56906597,56921822,56963320,57023523,57143218,57500808,57531883,57577157,57992940,58151119,59402651,59402653,59402654,59402655,59402656,59406230,59406231,59406232,59406233,59406234,59406235,59406236,59421287,59421291,59421298,59421308,59421351,59421352,59421389,59421399,59421403,59421435,59421463,59421467,59421471,59421474,59421499,59421511,59421557,59421568,59421605,59468951,",
        "milestoneIds": "",
        "milestones": 0,
        "name": "Vendetta",
        "objective": "<p>This threat actor appears to be focused on stealing information from the target by using remote access trojans to infect organizations.</p>",
        "onlineServiceIds": "",
        "signatureIds": "",
        "signatures": 0,
        "sophistication": "intermediate",
        "targetIds": "13,14,36,46,62,98,120,154,163,186,188,220,225,227,254,257,259,268,293,301,1164,",
        "targets": 21,
        "threatTypeIds": "",
        "toolIds": "136,193,",
        "tools": 2
    },
    "threatActor,ipIds": "96161121,",
    "threatContext": {
        "hasResults": "true"
    }
}
```

#### Human Readable Output

>### Blueliv Threat Actor info
>|active|aliases|country_name|created_at|description|first_seen|id|ioc_link|last_seen|links|modus_operandi|name|objective|references|sophistication|tlp|type|types|updated_at|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | Vendetta | Italy | 2020-06-10T11:23:22.584500Z | <h5>Key Points</h5><br/><br/><ul><br/>	<li><br/>	<p>Vendetta is a threat actor based on Italy or Turkey discovered in April 2020&nbsp;that seeks to steal targeted business intelligence.</p><br/>	</li><br/>	<li><br/>	<p>Vendetta targeted enterprises located in North America, Eastern Europe, Asia, and Oceania regions.</p><br/>	</li><br/>	<li>The threat actor uses social engineering techniques to infect the victims with a RAT.</li><br/></ul><br/><br/><h5>Assessment</h5><br/><br/><p>Vendetta is a Threat Actor that became active on April 2020, and was discovered by&nbsp;360 Baize Lab. The name comes from a PDB path found in one of the samples:</p><br/><br/><div style="background:#eeeeee; border:1px solid #cccccc; padding:5px 10px">C:\Users\<strong>Vendetta</strong>\source\repos\{project name}\*\obj\Debug\{project name}.pdb</div><br/><br/><p>Based on some information found on the samples themselves, and the tools used, 360 Baize Labs speculates that the actor is of European origin, either from Turkey or from Italy. Some of their malware samples contain the text &quot;Developers from Italy&quot; which indicates the threat actor may be Italian, but these also contain&nbsp;Turkish names in variables&nbsp;like RoboSky suggest they could actually be from Turkey.</p><br/><br/><p>Vendetta targeted its victims with highly convincing spearphishing emails, impersonating entities such as&nbsp;Australian Government Department of Health,&nbsp;Austrian Federal Ministry of the Interior (BMI), or the&nbsp;Mexican health department. The emails contained a malicious attachment called pdf.exe,&nbsp;trying to trick the victim into opening the executable file thinking it is a pdf file, which ultimately installed the <a href="https://thiapp2.blueliv.net/#/ui/intelligence/tools/details/136">NanoCore</a> and <a href="https://thiapp2.blueliv.net/#/ui/intelligence/tools/details/193">RemcosRAT</a> malware.</p> | 2020-04-01T00:00:00Z | 232 | https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/ioc/ | 2020-06-10T00:00:00Z | self: https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/ | <p>Vendetta uses well designed phishing campaigns to target businesses and individuals. The phishing emails contain a malicious payload that, once unleashed, will install a RAT in the infected computer.</p> | Vendetta | <p>This threat actor appears to be focused on stealing information from the target by using remote access trojans to infect organizations.</p> | {'link': 'https://blog.360totalsecurity.com/en/vendetta-new-threat-actor-from-europe/', 'title': 'Vendetta-new threat actor from Europe'} | intermediate | white | ThreatActor | hacker | 2020-06-10T12:29:16.463528Z |  |


### blueliv-tc-campaign
***
Gets information about a Campaign


#### Base Command

`blueliv-tc-campaign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| campaign | Name of the Campaign to search for | Optional | 
| campaign_id | Blueliv's internal Campaign id | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| campaign.name | Unknown | Campaign name | 
| campaign.description | Unknown | Campaign description | 
| campaign.lastSeen | Unknown | Campaign last seen | 
| campaign.botnets | Unknown | Campaign botnets | 
| campaign.botnetIds | Unknown | Campaign botnets internal IDs | 
| campaign.signatures | Unknown | Campaign signatures | 
| campaign.signatureIds | Unknown | Campaign signatures internal IDs | 
| campaign.ips | Unknown | Campaign IPs | 
| campaign.ipIds | Unknown | Campaign IPs internal IDs | 
| campaign.malware | Unknown | Campaign malware | 
| campaign.malwareIds | Unknown | Campaign malwares internal IDs | 
| campaign.attackPatterns | Unknown | Campaign attack patterns | 
| campaign.attackPatternIds | Unknown | Campaign attack patterns internal IDs | 
| campaign.tools | Unknown | Campaign tools | 
| campaign.toolIds | Unknown | Campaign tools internal IDs | 
| campaign.fqdns | Unknown | Campaign FQDNs | 
| campaign.fqdnIds | Unknown | Campaign FQDNs internal IDs | 
| campaign.threatActorId | Unknown | Campaign threat actors internal IDs | 


#### Command Example
```!blueliv-tc-campaign campaign_id=152```

#### Context Example
```
{
    "campaign": {
        "attackPatternIds": "",
        "attackPatterns": 0,
        "botnetIds": "",
        "botnets": 0,
        "description": "<p>A distribution campaign for the GRANDOREIRO banking Trojan. Through spam emails they got users to visit fake websites. The topic is usually electronic invoices, but recently they have used topics related to the coronavirus pandemic.</p>\n\n<p>There are different types of downloaders: VBS scripts, MSI files, executable downloaders.&nbsp;These downloaders contain an encoded URL that allows them to download an ISO file, usually hosted by a public service such as DROPBOX or GITHUB.</p>\n\n<p>This ISO file is actually a text file, which contains BASE64. Once decoded, a ZIP file containing GRANDOREIRO is obtained.</p>\n\n<p>Sometimes a password is required to extract the GRANDOREIRO trojan from the ZIP file. This prevents analyzing its content without analysing the downloader first.</p>",
        "fqdnIds": "138612,9322638,9394712,9549083,9549084,9549097,9549098,9549099,",
        "fqdns": 8,
        "ips": 0,
        "lastSeen": "2020-05-28T00:00:00Z",
        "malware": 9,
        "malwareIds": "55800558,55800615,58635752,58635753,58635754,58635755,58635756,58635757,58635758,",
        "name": "2020 Grandoreiro campaign against banks in LATAM, Portugal and Spain",
        "signatureIds": "",
        "signatures": 0,
        "threatActorId": "226",
        "toolIds": "673,",
        "tools": 1
    },
    "campaign,ipIds": "",
    "threatContext": {
        "hasResults": "true"
    }
}
```

#### Human Readable Output

>### Blueliv Campaign info
>|created_at|description|first_seen|id|ioc_link|last_seen|links|name|tlp|type|updated_at|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-05-28T21:24:11.307288Z | <p>A distribution campaign for the GRANDOREIRO banking Trojan. Through spam emails they got users to visit fake websites. The topic is usually electronic invoices, but recently they have used topics related to the coronavirus pandemic.</p><br/><br/><p>There are different types of downloaders: VBS scripts, MSI files, executable downloaders.&nbsp;These downloaders contain an encoded URL that allows them to download an ISO file, usually hosted by a public service such as DROPBOX or GITHUB.</p><br/><br/><p>This ISO file is actually a text file, which contains BASE64. Once decoded, a ZIP file containing GRANDOREIRO is obtained.</p><br/><br/><p>Sometimes a password is required to extract the GRANDOREIRO trojan from the ZIP file. This prevents analyzing its content without analysing the downloader first.</p> | 2020-04-16T00:00:00Z | 152 | https://tctrustoylo.blueliv.com/api/v1/campaign/152/ioc/ | 2020-05-28T00:00:00Z | self: https://tctrustoylo.blueliv.com/api/v1/campaign/152/ | 2020 Grandoreiro campaign against banks in LATAM, Portugal and Spain | white | Campaign | 2020-05-28T23:58:36.883515Z |  |


### blueliv-tc-attack-pattern
***
Gets information about a Attack Pattern


#### Base Command

`blueliv-tc-attack-pattern`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attackPattern | The Attack Pattern's name to search for | Optional | 
| attackPatternId | Interanl Blueliv's ID for the Attack Pattern | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| attackPattern.name | Unknown | Attack pattern name | 
| attackPattern.description | Unknown | Attack pattern description | 
| attackPattern.updatedAt | Unknown | Attack pattern updated at | 
| attackPattern.severity | Unknown | Attack pattern severity | 
| attackPattern.signatures | Unknown | Attack pattern signatures | 
| attackPattern.signatureIds | Unknown | Attack pattern signatures internal IDs | 
| attackPattern.campaigns | Unknown | Attack pattern campaigns | 
| attackPattern.campaignIds | Unknown | Attack pattern campaigns internal IDs | 
| attackPattern.threatActors | Unknown | Attack pattern threat actors | 
| attackPattern.threatActorIds | Unknown | Attack pattern threat actors internal IDs | 
| attackPattern.cves | Unknown | Attack pattern CVEs | 
| attackPattern.cveIds | Unknown | Attack pattern CVEs internal IDs | 


#### Command Example
```!blueliv-tc-attack-pattern attackPattern="Account Discovery"```

#### Context Example
```
{
    "attackPattern": {
        "campaignIds": "95,81,82,83,3,",
        "campaigns": 5,
        "cveIds": "",
        "cves": 0,
        "description": "Adversaries may attempt to get a listing of local system or domain accounts. \n\n### Windows\n\nExample commands that can acquire this information are <code>net user</code>, <code>net group <groupname></code>, and <code>net localgroup <groupname></code> using the [Net](https://attack.mitre.org/software/S0039) utility or through use of [dsquery](https://attack.mitre.org/software/S0105). If adversaries attempt to identify the primary user, currently logged in user, or set of users that commonly uses a system, [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) may apply.\n\n### Mac\n\nOn Mac, groups can be enumerated through the <code>groups</code> and <code>id</code> commands. In mac specifically, <code>dscl . list /Groups</code> and <code>dscacheutil -q group</code> can also be used to enumerate groups and users.\n\n### Linux\n\nOn Linux, local users can be enumerated through the use of the <code>/etc/passwd</code> file which is world readable. In mac, this same file is only used in single-user mode in addition to the <code>/etc/master.passwd</code> file.\n\nAlso, groups can be enumerated through the <code>groups</code> and <code>id</code> commands.",
        "name": "Account Discovery",
        "serverity": "Medium",
        "signatureIds": "",
        "signatures": 0,
        "threatActorIds": "1,34,62,21,131,56,89,191,47,8,81,10,50,28,37,194,228,190,",
        "threatActors": 18,
        "updatedAt": "2018-12-24T23:00:02.352102Z"
    },
    "threatContext": {
        "hasResults": "true"
    }
}
```

#### Human Readable Output

>### Blueliv Attack Pattern info
>|attack_phases|attacker_skills_or_knowledge_required|capec_id|created_at|description|id|links|name|prerequisites|purposes|references|related_vulnerabilities|related_weaknesses|severity|solutions_and_mitigations|tlp|type|updated_at|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  |  | 2018-12-24T23:00:02.352087Z | Adversaries may attempt to get a listing of local system or domain accounts. <br/><br/>### Windows<br/><br/>Example commands that can acquire this information are <code>net user</code>, <code>net group &lt;groupname&gt;</code>, and <code>net localgroup &lt;groupname&gt;</code> using the [Net](https://attack.mitre.org/software/S0039) utility or through use of [dsquery](https://attack.mitre.org/software/S0105). If adversaries attempt to identify the primary user, currently logged in user, or set of users that commonly uses a system, [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) may apply.<br/><br/>### Mac<br/><br/>On Mac, groups can be enumerated through the <code>groups</code> and <code>id</code> commands. In mac specifically, <code>dscl . list /Groups</code> and <code>dscacheutil -q group</code> can also be used to enumerate groups and users.<br/><br/>### Linux<br/><br/>On Linux, local users can be enumerated through the use of the <code>/etc/passwd</code> file which is world readable. In mac, this same file is only used in single-user mode in addition to the <code>/etc/master.passwd</code> file.<br/><br/>Also, groups can be enumerated through the <code>groups</code> and <code>id</code> commands. | 686 | self: https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/ | Account Discovery |  |  |  |  |  | Medium |  | white | AttackPattern | 2018-12-24T23:00:02.352102Z | 72b74d71-8169-42aa-92e0-e7b04b9f5a08 |


### blueliv-tc-tool
***
Gets information about a Tool


#### Base Command

`blueliv-tc-tool`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tool | Tool's name to search for | Optional | 
| tool_id | Internal Blueliv's id of the tool | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| tool.Name | Unknown | Tool Name | 
| tool.description | Unknown | Tool description | 
| tool.lastSeen | Unknown | Tool last seen | 
| tool.campaigns | Unknown | Tool campaigns | 
| tool.campaignIds | Unknown | Tool campaigns internal IDs | 
| tool.signatures | Unknown | Tool signatures | 
| tool.signatureIds | Unknown | Tool signatures internal IDs | 
| tool.threatActors | Unknown | Tool threat actors | 
| tool.threatActorIds | Unknown | Tool threat actors internal IDs | 


#### Command Example
```!blueliv-tc-tool tool=ACEHASH```

#### Context Example
```
{
    "threatContext": {
        "hasResults": "true"
    },
    "tool": {
        "campaignIds": "",
        "campaigns": 0,
        "description": "<p>ACEHASH is a credential theft/password hash dumping utility. The code may be based in Mimikatz and appears to be publicly available.</p>",
        "lastSeen": "2019-12-01T00:00:00Z",
        "name": "ACEHASH",
        "signatureIds": "",
        "signatures": 0,
        "threatActorIds": "194,",
        "threatActors": 1
    }
}
```

#### Human Readable Output

>### Blueliv Tool info
>|created_at|description|discovery_date|first_seen|id|last_seen|links|name|references|targeted_platforms|tlp|type|updated_at|uuid|version|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-02-26T14:35:55.698486Z | <p>ACEHASH is a credential theft/password hash dumping utility. The code may be based in Mimikatz and appears to be publicly available.</p> |  | 2012-12-01T00:00:00Z | 532 | 2019-12-01T00:00:00Z | self: https://tctrustoylo.blueliv.com/api/v1/tool/532/ | ACEHASH | {'link': 'https://content.fireeye.com/apt-41/rpt-apt41', 'title': 'Double Dragon: APT41, a dual espionage and cyber crime operation'} |  | white | Tool | 2020-02-26T14:35:55.698549Z |  |  |


### blueliv-tc-signature
***
Gets information about a Signature


#### Base Command

`blueliv-tc-signature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| signature | Signature's name to search for | Optional | 
| signature_id | Internal Blueliv's ID for the signature | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| signature.name | Unknown | Signature name | 
| signature.updatedAt | Unknown | Signature updated at | 
| signature.ipIds | Unknown | Signature IPs internal IDs | 
| signature.malware | Unknown | Signature malware | 
| signature.malwareIds | Unknown | Signature malwares internal IDs | 
| signature.score | Unknown | Signature score | 


#### Command Example
```!blueliv-tc-signature signature_id=84458```

#### Context Example
```
{
    "signature": {
        "malware": 0,
        "malwareIds": "",
        "name": "ET TROJAN DonotGroup Staging Domain in DNS Query (sid 2030333)",
        "type": "snort",
        "updatedAt": "2020-06-15T02:11:21.962364Z"
    },
    "threatContext": {
        "hasResults": "true"
    }
}
```

#### Human Readable Output

>### Blueliv Signature info
>|created_at|id|links|name|references|sid|signature|status|tlp|type|updated_at|version|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-06-15T02:11:21.962302Z | 84458 | self: https://tctrustoylo.blueliv.com/api/v1/signature/84458/ | ET TROJAN DonotGroup Staging Domain in DNS Query (sid 2030333) |  | 2030333 | alert udp $HOME_NET any -> any 53 (msg:"ET TROJAN DonotGroup Staging Domain in DNS Query"; content:"\|01\|"; offset:2; depth:1; content:"\|00 01 00 00 00 00 00\|"; distance:1; within:7; content:"\|0c\|yourcontents\|03\|xyz\|00\|"; distance:0; fast_pattern; metadata: former_category MALWARE; classtype:trojan-activity; sid:2030333; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2020_06_12, updated_at 2020_06_12;) | enabled | white | snort | 2020-06-15T02:11:21.962364Z | 2 |

