Provides URL scanning and rewriting of inbound email messages in mail flow, and time-of-click verification of URLs and links in email messages and other locations.
This integration was integrated and tested with Exchange Online PowerShell V2 module, and [Defender for Office 365](https://docs.microsoft.com/en-us/powershell/module/exchange/?view=exchange-ps#defender-for-office-365). 

[The Safe Links Product overview](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links?view=o365-worldwide)

### Required Permissions
___
* In the Azure Application, give the following application permission:
    * Office 365 Exchange Online -> Exchange.ManageAsApp - Application
* To create, modify, and delete Safe Links policies, or use any of the report commands (detailed or aggregate report), you need to be a member of the `Organization Management` or `Security Administrator` role groups.
* To manage permissions in the Microsoft Defender XDR portal, go to `Permissions & roles` or https://security.microsoft.com/securitypermissions. You need to be a global administrator or a member of the Organization Management role group in the Microsoft Defender XDR portal. Specifically, the Role Management role allows users to view, create, and modify role groups in the Microsoft Defender XDR portal, and by default, that role is assigned only to the Organization Management role group. See [Permissions in the Microsoft Defender XDR portal](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/permissions-microsoft-365-security-center?view=o365-worldwide)


## Configure O365 Defender SafeLinks in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Certificate | A pfx certificate encoded in Base64. | True |
| Password - Used to generate the certificate |  | True |
| Organization | The organization used in app-only authentication. | True |
| The application ID from the Azure portal |  | True |


### Important Notes
---
* It is strongly recommended to follow the [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide), to prevent the docker container from utilizing excessive memory. Details about the known memory leak can be found [here](https://github.com/MicrosoftDocs/office-docs-powershell/issues/6924).
* If your instance does experience memory management issues, please configure your playbooks to use *Retry on error*.

### Safe Links Rule and Policy
___
The basic elements of a Safe Links policy are:

**The safe links policy**: Turn on Safe Links protection, turn on real-time URL scanning, specify whether to wait for real-time scanning to complete before delivering the message, turn on scanning for internal messages, specify whether to track user clicks on URLs, and specify whether to allow users to click trough to the original URL.
**The safe links rule**: Specifies the priority and recipient filters (who the policy applies to).
The difference between these two elements isn't obvious when you manage Safe Links policies in the Microsoft Defender XDR portal:

When you create a Safe Links policy, you're actually creating a safe links rule and the associated safe links policy at the same time using the same name for both.
When you modify a Safe Links policy, settings related to the name, priority, enabled or disabled, and recipient filters modify the safe links rule. All other settings modify the associated safe links policy.
When you remove a Safe Links policy, the safe links rule and the associated safe links policy are removed.
In Exchange Online PowerShell or standalone EOP PowerShell, you manage the policy and the rule separately.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### o365-defender-safelinks-policy-list
***
List the Safe Links policies in your cloud-based organization.


#### Base Command

`o365-defender-safelinks-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The identity of the Safe Links policy that you want to view. Available identity fields of the policy are: Name, Distinguished name (DN), and GUID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365Defender.SafeLinks.AdminDisplayName | String | Policy description. | 
| O365Defender.SafeLinks.Policy.AllowClickThrough | Boolean | Whether users are allowed to click through the original URL. | 
| O365Defender.SafeLinks.Policy.CustomNotificationText | String | The customized notification text to show to users. | 
| O365Defender.SafeLinks.Policy.DeliverMessageAfterScan | Boolean | Whether the mail is delivered after Safe Links scanning was completed. | 
| O365Defender.SafeLinks.Policy.DisableUrlRewrite | Boolean | Whether URLs are rewritten \(wrapped\) in email messages. | 
| O365Defender.SafeLinks.Policy.DistinguishedName | String | Policy distinguished name \(DN\). | 
| O365Defender.SafeLinks.Policy.DoNotAllowClickThrough | Boolean | Whether users can click through the original URLs. | 
| O365Defender.SafeLinks.Policy.DoNotTrackUserClicks | Boolean | Whether user clicks are tracked. | 
| O365Defender.SafeLinks.Policy.DoNotRewriteUrls | Unknown | List of URLs that are not rewritten by Safe Links scanning. | 
| O365Defender.SafeLinks.Policy.EnableForInternalSenders | Boolean | Whether the Safe Links policy is applied to messages sent between internal senders and internal recipients within the same Exchange Online organization. | 
| O365Defender.SafeLinks.Policy.EnableOrganizationBranding | Boolean | Whether the organization's logo is displayed on Safe Links warning and notification pages. | 
| O365Defender.SafeLinks.Policy.EnableSafeLinksForTeams | Boolean | Whether the Safe Links policy is enabled for Microsoft Teams. | 
| O365Defender.SafeLinks.Policy.ExchangeObjectId | String | Exchange object ID. | 
| O365Defender.SafeLinks.Policy.ExchangeVersion | String | The version of the Exchange server. | 
| O365Defender.SafeLinks.Policy.Guid | String | The GUID of the Safe Links policy. | 
| O365Defender.SafeLinks.Policy.Id | String | The ID of the Safe Links policy. | 
| O365Defender.SafeLinks.Policy.Identity | String | The identity of the Safe Links policy. | 
| O365Defender.SafeLinks.Policy.IsDefault | Boolean | Whether the Safe Links policy is the default policy. | 
| O365Defender.SafeLinks.Policy.IsEnabled | Boolean | Whether Safe Links protection is enabled for email messages. | 
| O365Defender.SafeLinks.Policy.IsValid | Boolean | Whether the Safe Links policy is valid. | 
| O365Defender.SafeLinks.Policy.Name | String | Policy name. | 
| O365Defender.SafeLinks.Policy.ObjectState | String | The Safe Links policy state. | 
| O365Defender.SafeLinks.Policy.OrganizationId | String | The organization ID. | 
| O365Defender.SafeLinks.Policy.ScanUrls | Boolean | Whether real-time scanning of clicked links in email messages is enabled. | 
| O365Defender.SafeLinks.Policy.WhenChanged | Date | The date and time the Safe Links policy was modified. Time format: YYYY-MM-DDThh:mm:ss\+00:00. | 
| O365Defender.SafeLinks.Policy.WhenChangedUTC | Date | The date and time \(in UTC\) the  Safe Links policy was modified. Time format: YYYY-MM-DDTHH:MM:SSZ. | 
| O365Defender.SafeLinks.Policy.WhenCreated | Date | The date and time the Safe Links policy was created. Time format: YYYY-MM-DDThh:mm:ss\+00:00. | 
| O365Defender.SafeLinks.Policy.WhenCreatedUTC | Date | The date and time \(in UTC\) the Safe Links policy was created. Time format: YYYY-MM-DDTHH:MM:SSZ. | 


#### Command Example
```!o365-defender-safelinks-policy-list```

#### Context Example
```json
{
  "O365Defender.SafeLinks.Policy(obj.Guid === val.Guid)": [
    {
      "AdminDisplayName": "Few URL",
      "AllowClickThrough": true,
      "CustomNotificationText": "Sorry, you cant click through this URL",
      "DeliverMessageAfterScan": false,
      "DisableUrlRewrite": false,
      "DistinguishedName": "CN=XSOAR Policy,CN=Safe Links,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM",
      "DoNotAllowClickThrough": false,
      "DoNotRewriteUrls": [
        "www.test.com",
        "https://xsoar.test.com"
      ],
      "DoNotTrackUserClicks": false,
      "EnableForInternalSenders": false,
      "EnableOrganizationBranding": false,
      "EnableSafeLinksForTeams": false,
      "ExchangeObjectId": "5796cea3-cfdb-4a99-9956-bf62209118a6",
      "ExchangeVersion": "0.20 (15.0.0.0)",
      "ExcludedUrls": [
        "www.test.com",
        "https://xsoar.test.com"
      ],
      "Guid": "5796cea3-cfdb-4a99-9956-bf62209118a6",
      "Id": "XSOAR Policy",
      "Identity": "XSOAR Policy",
      "IsBuiltInProtection": false,
      "IsDefault": false,
      "IsEnabled": true,
      "IsValid": true,
      "LocalizedNotificationTextList": [
        "[zh-Hant, 對不起，你不能點擊通過這個網址]",
        "[af, Jammer, jy kan nie deur hierdie URL klik nie]",
        "[hi, क्षमा करें, आप इस यूआरएल के माध्यम से क्लिक नहीं कर सकते]",
        "[ja, この URL をクリックできません。]",
        "[otq, Nä'ä di tsa̲hu̲, hingi tsa̲ o̲t'e clic nuna ar URL]",
        "[zh-Hans, 对不起，你不能点击通过这个网址]",
        "[ur, معذرت، آپ اس یو آر ایل کے ذریعے کلک نہیں کر سکتے]",
        "[ht, Padon, ou pa klike sou URL sa a]",
        "[it, Siamo spiacenti, non puoi fare clic su questo URL]",
        "[ms, Maaf, anda tidak boleh klik melalui URL ini]",
        "[bs, Žao mi je, ne možete kliknuti kroz ovaj URL]",
        "[cs, Je nám líto, ale nemůžete kliknout na tuto adresu URL]",
        "[mt, Jiddispjaċina, ma tistax tikklikkja permezz ta' dan il-URL]",
        "[fa, با عرض پوزش، شما نمی توانید از طریق این آدرس کلیک کنید]",
        "[ga, Ár leithscéal, ní féidir leat cliceáil tríd an URL seo]",
        "[da, Beklager, men du kan ikke klikke dig igennem denne URL-adresse]",
        "[hr, Nažalost, ne možete kliknuti kroz ovaj URL]",
        "[he, מצטערים, אתה לא יכול ללחוץ על כתובת URL זו]",
        "[et, Kahjuks ei saa te seda URL-i klõpsata]",
        "[tr, Üzgünüz, bu URL'yi tıklatamazsınız]",
        "[ru, Извините, вы не можете щелкнуть по этому URL-адресу]",
        "[nb, Beklager, du kan ikke klikke deg gjennom denne URL-adressen]",
        "[ar, عذرا، أنت غير قادر على النقر من خلال هذا العنوان]",
        "[fr, Désolé, vous ne pouvez pas cliquer sur cette URL]",
        "[sv, Tyvärr kan du inte klicka igenom den här URL:en]",
        "[tlh-Piqd,      ]",
        "[de, Es tut uns leid, aber Sie können sich nicht durch diese URL klicken]",
        "[id, Maaf, Anda tidak bisa mengklik URL ini]",
        "[kk, Кешіріңіз, осы URL мекенжайы арқылы басуға болмайды]",
        "[lv, Atvainojiet, jūs nevarat noklikšķināt caur šo URL]",
        "[yue, 对唔住，你唔可以點擊透過呢個網址]",
        "[nl, Sorry, u kunt niet door deze URL klikken]",
        "[ro, Ne pare rău, tu cant faceți clic prin acest URL-ul]",
        "[ml, ക്ഷമിക്കണം, ഈ യുആർഎൽ വഴി ക്ലിക്ക് ചെയ്യാൻ നിങ്ങൾക്ക് കഴിയില്ല]",
        "[sw, Samahani, unaweza kubofya kupitia URL hii]",
        "[sl, Žal ne morete klikati preko tega URL-ja]",
        "[th, ขออภัย คุณไม่สามารถคลิกผ่าน URL นี้]",
        "[to, Kātaki fakamolemole, he ʻikai lava ke ke lomiʻi ʻi he URL ko ʻení]",
        "[pt-PT, Desculpe, não pode clicar neste URL]",
        "[ca, Ho sentim, no podeu fer clic a través d'aquesta URL]",
        "[ko, 죄송합니다, 이 URL을 클릭할 수 없습니다.]",
        "[el, Δυστυχώς, δεν μπορείτε να κάνετε κλικ σε αυτήν τη διεύθυνση URL]",
        "[fil, Paumanhin, maaari mong i-click sa pamamagitan ng URL na ito]",
        "[fj, Vosota, e sega ni rawa ni o kiliki ena URL oqo]",
        "[cy, Mae'n ddrwg gennym, gallwch glicio drwy'r URL hwn]",
        "[hu, Sajnáljuk, nem kattinthat át ezen az URL-címen]",
        "[pt, Desculpe, você não pode clicar através desta URL]",
        "[kn, ಕ್ಷಮಿಸಿ, ಈ ಯುಆರ್ ಎಲ್ ಮೂಲಕ ನೀವು ಕ್ಲಿಕ್ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ]",
        "[pl, Przepraszamy, nie możesz kliknąć tego adresu URL]",
        "[bn, দুঃখিত, আপনি এই ইউআরএল-এর মাধ্যমে ক্লিক করতে পারবেন না]",
        "[vi, Xin lỗi, bạn không thể nhấp qua URL này]",
        "[gu, માફ કરશો, તમે આ યુઆરએલ દ્વારા ક્લિક કરી શકતા નથી]",
        "[sr-Cyrl, Жао нам је, не можете кликнути кроз ову УРЛ адресу]",
        "[sr-Latn, Žao nam je, ne možete kliknuti kroz ovu URL adresu]",
        "[sk, Ľutujeme, nemôžete kliknúť na túto adresu URL]",
        "[en, Sorry, you cant click through this URL]",
        "[uk, На жаль, ви нахиляє натисніть через цю URL-адресу]",
        "[mi, Aroha mai, kāore e taea te pāwhiri mā tēnei URL]",
        "[sm, Faamalie atu, e le mafai ona e kiliki i le URL lenei]",
        "[fi, Valitettavasti et voi napsauttaa tätä URL-osoitetta]",
        "[lt, Atsiprašome, jūs negalite spustelėti per šį URL]",
        "[bg, Съжаляваме, можете да кликнете чрез този URL адрес]",
        "[te, క్షమించండి, ఈ యుఆర్ ఎల్ ద్వారా మీరు క్లిక్ చేయలేరు]",
        "[is, Því miður geturðu ekki smellt í gegnum þessa slóð]",
        "[ta, மன்னிக்கவும், இந்த யுஆர்எல் வழியாக கிளிக் செய்ய முடியாது]",
        "[tlh-Latn, taHqeq mIv'a' tIqwIj, qaStaHvIS poH nI''e']",
        "[mww, Thov txim, koj yuav nias los ntawm no URL]",
        "[es, Lo sentimos, no puedes hacer clic en esta URL]",
        "[pa, ਮਾਫ਼ ਕਰਨਾ, ਤੁਸੀਂ ਇਸ ਯੂਆਰਐਲ ਰਾਹੀਂ ਕਲਿੱਕ ਨਹੀਂ ਕਰ ਸਕਦੇ]",
        "[mg, Miala tsiny fa tsy afaka manindry ity URL ity ianao]"
      ],
      "Name": "XSOAR Policy",
      "ObjectCategory": "EURPR07A123.PROD.OUTLOOK.COM/Configuration/Schema/ms-Exch-Smart-Links-Protection-Config",
      "ObjectClass": [
        "top",
        "msExchSmartLinksProtectionConfig"
      ],
      "ObjectState": "Unchanged",
      "OrganizationId": "EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration",
      "OrganizationalUnitRoot": "xsoartest.onmicrosoft.com",
      "OriginatingServer": "AM7PR07A05DC123.EURPR07A123.PROD.OUTLOOK.COM",
      "PSComputerName": "outlook.office365.com",
      "PSShowComputerName": false,
      "RecommendedPolicyType": "Custom",
      "RunspaceId": "8501abb8-6d7c-45ca-bc0d-4c260d68d248",
      "ScanUrls": false,
      "TrackClicks": true,
      "WhenChanged": "2021-10-21T12:49:09+00:00",
      "WhenChangedUTC": "2021-10-21T12:49:09Z",
      "WhenCreated": "2021-10-21T12:49:03+00:00",
      "WhenCreatedUTC": "2021-10-21T12:49:03Z",
      "WhiteListedUrls": "www.test.com,https://xsoar.test.com"
    }
  ]
}

```

#### Human Readable Output
>### Results of o365-defender-safelinks-policy-list
>| AdminDisplayName | AllowClickThrough | CustomNotificationText | DeliverMessageAfterScan | DisableUrlRewrite | DistinguishedName | DoNotAllowClickThrough | DoNotRewriteUrls | DoNotTrackUserClicks | EnableForInternalSenders | EnableOrganizationBranding | EnableSafeLinksForTeams | ExchangeObjectId | ExchangeVersion | ExcludedUrls | Guid | Id | Identity | IsBuiltInProtection | IsDefault | IsEnabled | IsValid | LocalizedNotificationTextList | Name | ObjectCategory | ObjectClass | ObjectState | OrganizationalUnitRoot | OrganizationId | OriginatingServer | PSComputerName | PSShowComputerName | RecommendedPolicyType | RunspaceId | ScanUrls | TrackClicks | WhenChanged | WhenChangedUTC | WhenCreated | WhenCreatedUTC | WhiteListedUrls
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Few URL | true | Sorry, you cant click through this URL | false | false | CN=XSOAR Policy,CN=Safe Links,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM | false | ["www.test.com","https://xsoar.test.com"] | false | false | false | false | {"value":"5796cea3-cfdb-4a99-9956-bf62209118a6","Guid":"5796cea3-cfdb-4a99-9956-bf62209118a6"} | 0.20 (15.0.0.0) | ["www.test.com","https://xsoar.test.com"] | {"value":"5796cea3-cfdb-4a99-9956-bf62209118a6","Guid":"5796cea3-cfdb-4a99-9956-bf62209118a6"} | XSOAR Policy | XSOAR Policy | false | false | true | true | ["[zh-Hant, 對不起，你不能點擊通過這個網址]","[af, Jammer, jy kan nie deur hierdie URL klik nie]","[hi, क्षमा करें, आप इस यूआरएल के माध्यम से क्लिक नहीं कर सकते]","[ja, この URL をクリックできません。]","[otq, Nä'ä di tsa̲hu̲, hingi tsa̲ o̲t'e clic nuna ar URL]","[zh-Hans, 对不起，你不能点击通过这个网址]","[ur, معذرت، آپ اس یو آر ایل کے ذریعے کلک نہیں کر سکتے]","[ht, Padon, ou pa klike sou URL sa a]","[it, Siamo spiacenti, non puoi fare clic su questo URL]","[ms, Maaf, anda tidak boleh klik melalui URL ini]","[bs, Žao mi je, ne možete kliknuti kroz ovaj URL]","[cs, Je nám líto, ale nemůžete kliknout na tuto adresu URL]","[mt, Jiddispjaċina, ma tistax tikklikkja permezz ta' dan il-URL]","[fa, با عرض پوزش، شما نمی توانید از طریق این آدرس کلیک کنید]","[ga, Ár leithscéal, ní féidir leat cliceáil tríd an URL seo]","[da, Beklager, men du kan ikke klikke dig igennem denne URL-adresse]","[hr, Nažalost, ne možete kliknuti kroz ovaj URL]","[he, מצטערים, אתה לא יכול ללחוץ על כתובת URL זו]","[et, Kahjuks ei saa te seda URL-i klõpsata]","[tr, Üzgünüz, bu URL'yi tıklatamazsınız]","[ru, Извините, вы не можете щелкнуть по этому URL-адресу]","[nb, Beklager, du kan ikke klikke deg gjennom denne URL-adressen]","[ar, عذرا، أنت غير قادر على النقر من خلال هذا العنوان]","[fr, Désolé, vous ne pouvez pas cliquer sur cette URL]","[sv, Tyvärr kan du inte klicka igenom den här URL:en]","[tlh-Piqd,      ]","[de, Es tut uns leid, aber Sie können sich nicht durch diese URL klicken]","[id, Maaf, Anda tidak bisa mengklik URL ini]","[kk, Кешіріңіз, осы URL мекенжайы арқылы басуға болмайды]","[lv, Atvainojiet, jūs nevarat noklikšķināt caur šo URL]","[yue, 对唔住，你唔可以點擊透過呢個網址]","[nl, Sorry, u kunt niet door deze URL klikken]","[ro, Ne pare rău, tu cant faceți clic prin acest URL-ul]","[ml, ക്ഷമിക്കണം, ഈ യുആർഎൽ വഴി ക്ലിക്ക് ചെയ്യാൻ നിങ്ങൾക്ക് കഴിയില്ല]","[sw, Samahani, unaweza kubofya kupitia URL hii]","[sl, Žal ne morete klikati preko tega URL-ja]","[th, ขออภัย คุณไม่สามารถคลิกผ่าน URL นี้]","[to, Kātaki fakamolemole, he ʻikai lava ke ke lomiʻi ʻi he URL ko ʻení]","[pt-PT, Desculpe, não pode clicar neste URL]","[ca, Ho sentim, no podeu fer clic a través d'aquesta URL]","[ko, 죄송합니다, 이 URL을 클릭할 수 없습니다.]","[el, Δυστυχώς, δεν μπορείτε να κάνετε κλικ σε αυτήν τη διεύθυνση URL]","[fil, Paumanhin, maaari mong i-click sa pamamagitan ng URL na ito]","[fj, Vosota, e sega ni rawa ni o kiliki ena URL oqo]","[cy, Mae'n ddrwg gennym, gallwch glicio drwy'r URL hwn]","[hu, Sajnáljuk, nem kattinthat át ezen az URL-címen]","[pt, Desculpe, você não pode clicar através desta URL]","[kn, ಕ್ಷಮಿಸಿ, ಈ ಯುಆರ್ ಎಲ್ ಮೂಲಕ ನೀವು ಕ್ಲಿಕ್ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ]","[pl, Przepraszamy, nie możesz kliknąć tego adresu URL]","[bn, দুঃখিত, আপনি এই ইউআরএল-এর মাধ্যমে ক্লিক করতে পারবেন না]","[vi, Xin lỗi, bạn không thể nhấp qua URL này]","[gu, માફ કરશો, તમે આ યુઆરએલ દ્વારા ક્લિક કરી શકતા નથી]","[sr-Cyrl, Жао нам је, не можете кликнути кроз ову УРЛ адресу]","[sr-Latn, Žao nam je, ne možete kliknuti kroz ovu URL adresu]","[sk, Ľutujeme, nemôžete kliknúť na túto adresu URL]","[en, Sorry, you cant click through this URL]","[uk, На жаль, ви нахиляє натисніть через цю URL-адресу]","[mi, Aroha mai, kāore e taea te pāwhiri mā tēnei URL]","[sm, Faamalie atu, e le mafai ona e kiliki i le URL lenei]","[fi, Valitettavasti et voi napsauttaa tätä URL-osoitetta]","[lt, Atsiprašome, jūs negalite spustelėti per šį URL]","[bg, Съжаляваме, можете да кликнете чрез този URL адрес]","[te, క్షమించండి, ఈ యుఆర్ ఎల్ ద్వారా మీరు క్లిక్ చేయలేరు]","[is, Því miður geturðu ekki smellt í gegnum þessa slóð]","[ta, மன்னிக்கவும், இந்த யுஆர்எல் வழியாக கிளிக் செய்ய முடியாது]","[tlh-Latn, taHqeq mIv'a' tIqwIj, qaStaHvIS poH nI''e']","[mww, Thov txim, koj yuav nias los ntawm no URL]","[es, Lo sentimos, no puedes hacer clic en esta URL]","[pa, ਮਾਫ਼ ਕਰਨਾ, ਤੁਸੀਂ ਇਸ ਯੂਆਰਐਲ ਰਾਹੀਂ ਕਲਿੱਕ ਨਹੀਂ ਕਰ ਸਕਦੇ]","[mg, Miala tsiny fa tsy afaka manindry ity URL ity ianao]"] | XSOAR Policy | EURPR07A123.PROD.OUTLOOK.COM/Configuration/Schema/ms-Exch-Smart-Links-Protection-Config | ["top","msExchSmartLinksProtectionConfig"] | Unchanged | xsoartest.onmicrosoft.com | EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration | AM7PR07A05DC123.EURPR07A123.PROD.OUTLOOK.COM | outlook.office365.com | false | Custom | {"value":"8501abb8-6d7c-45ca-bc0d-4c260d68d248","Guid":"8501abb8-6d7c-45ca-bc0d-4c260d68d248"} | false | true | {"value":"2021-10-21T12:49:09+00:00","DateTime":"Thursday, October 21, 2021 12:49:09 PM"} | {"value":"2021-10-21T12:49:09Z","DateTime":"Thursday, October 21, 2021 12:49:09 PM"} | {"value":"2021-10-21T12:49:03+00:00","DateTime":"Thursday, October 21, 2021 12:49:03 PM"} | {"value":"2021-10-21T12:49:03Z","DateTime":"Thursday, October 21, 2021 12:49:03 PM"} | www.test.com,https://xsoar.test.com



### o365-defender-safelinks-policy-create
***
Create a new Safe Links policy.


#### Base Command

`o365-defender-safelinks-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A unique name for the Safe Links policy. | Required | 
| admin_display_name | The description for the policy. | Optional | 
| custom_notification_text | The custom notification text to show to users. | Optional | 
| deliver_message_after_scan | Whether to deliver email messages only after Safe Links scanning was completed. When true, messages that contain malicious links are not delivered. Default is false. Possible values are: true, false. | Optional | 
| do_not_allow_click_through | Whether to allow users to click through to the original URL on warning pages. Default is false. Possible values are: true, false. | Optional | 
| do_not_rewrite_urls | Comma-separated list of URLs that are not rewritten by Safe Links scanning. | Optional | 
| do_not_track_user_clicks | Whether to track user clicks related to Safe Links protection of links in email messages. Default is false. Possible values are: true, false. | Optional | 
| enable_for_internal_senders | Whether the Safe Links policy is applied to messages sent between internal senders and internal recipients within the same Exchange Online organization.Default is false. Possible values are: true, false. | Optional | 
| enable_organization_branding | Whether to display the organization's logo on Safe Links warning and notification pages. Default is false. Possible values are: true, false. | Optional | 
| enable_safe_links_for_teams | Whether to enable Safe Links for Microsoft Teams. Default is false. Possible values are: true, false. | Optional | 
| is_enabled | Whether to enable Safe Links protection for email messages. Default is false. Possible values are: true, false. | Optional | 
| scan_urls | Whether to enable or disable real-time scanning of clicked links in email messages. Default is false. Possible values are: true, false. | Optional | 
| use_translated_notification_text | Whether to use Microsoft Translator to automatically localize the custom notification text that you specified with the CustomNotificationText parameter. Default is false. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365Defender.SafeLinks.AdminDisplayName | String | Policy description. | 
| O365Defender.SafeLinks.Policy.AllowClickThrough | Boolean | Whether users are allowed to click through the original URL. | 
| O365Defender.SafeLinks.Policy.CustomNotificationText | String | The customized notification text to show to users. | 
| O365Defender.SafeLinks.Policy.DeliverMessageAfterScan | Boolean | Whether the mail is delivered after Safe Links scanning was completed. | 
| O365Defender.SafeLinks.Policy.DisableUrlRewrite | Boolean | Whether URLs are rewritten \(wrapped\) in email messages. | 
| O365Defender.SafeLinks.Policy.DistinguishedName | String | Policy distinguished name \(DN\). | 
| O365Defender.SafeLinks.Policy.DoNotAllowClickThrough | Boolean | Whether users can click through the original URLs. | 
| O365Defender.SafeLinks.Policy.DoNotTrackUserClicks | Boolean | Whether user clicks are tracked. | 
| O365Defender.SafeLinks.Policy.DoNotRewriteUrls | Unknown | List of URLs that are not rewritten by Safe Links scanning. | 
| O365Defender.SafeLinks.Policy.EnableForInternalSenders | Boolean | Whether the Safe Links policy is applied to messages sent between internal senders and internal recipients within the same Exchange Online organization. | 
| O365Defender.SafeLinks.Policy.EnableOrganizationBranding | Boolean | Whether the organization's logo is displayed on Safe Links warning and notification pages. | 
| O365Defender.SafeLinks.Policy.EnableSafeLinksForTeams | Boolean | Whether the Safe Links policy is enabled for Microsoft Teams. | 
| O365Defender.SafeLinks.Policy.ExchangeObjectId | String | Exchange object ID. | 
| O365Defender.SafeLinks.Policy.ExchangeVersion | String | The version of the Exchange server. | 
| O365Defender.SafeLinks.Policy.Guid | String | The GUID of the Safe Links policy. | 
| O365Defender.SafeLinks.Policy.Id | String | The ID of the Safe Links policy. | 
| O365Defender.SafeLinks.Policy.Identity | String | The identity of the Safe Links policy. | 
| O365Defender.SafeLinks.Policy.IsDefault | Boolean | Whether the Safe Links policy is the default policy. | 
| O365Defender.SafeLinks.Policy.IsEnabled | Boolean | Whether Safe Links protection is enabled for email messages. | 
| O365Defender.SafeLinks.Policy.IsValid | Boolean | Whether the Safe Links policy is valid. | 
| O365Defender.SafeLinks.Policy.Name | String | Policy name. | 
| O365Defender.SafeLinks.Policy.ObjectState | String | The Safe Links policy state. | 
| O365Defender.SafeLinks.Policy.OrganizationId | String | The organization ID. | 
| O365Defender.SafeLinks.Policy.ScanUrls | Boolean | Whether real-time scanning of clicked links in email messages is enabled. | 
| O365Defender.SafeLinks.Policy.WhenChanged | Date | The date and time the Safe Links policy was modified. Time format: YYYY-MM-DDThh:mm:ss\+00:00. | 
| O365Defender.SafeLinks.Policy.WhenChangedUTC | Date | The date and time \(in UTC\) the Safe Links policy was modified. Time format: YYYY-MM-DDTHH:MM:SSZ | 
| O365Defender.SafeLinks.Policy.WhenCreated | Date | The date and time the Safe Links policy was created. Time format: YYYY-MM-DDThh:mm:ss\+00:00. | 
| O365Defender.SafeLinks.Policy.WhenCreatedUTC | Date | The date and time \(in UTC\) the Safe Links policy was created. Time format: YYYY-MM-DDTHH:MM:SSZ | 


#### Command Example
```o365-defender-safelinks-policy-create name=xsoartest admin_display_name="Description for policy" do_not_allow_click_through=true```

#### Context Example
```json
{
  "O365Defender.SafeLinks.Policy(obj.Guid === val.Guid)": [
    {
      "AdminDisplayName": "Few URL",
      "AllowClickThrough": true,
      "CustomNotificationText": "Sorry, you cant click through this URL",
      "DeliverMessageAfterScan": false,
      "DisableUrlRewrite": false,
      "DistinguishedName": "CN=xsoartest,CN=Safe Links,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM",
      "DoNotAllowClickThrough": false,
      "DoNotRewriteUrls": [
        "www.test.com",
        "https://xsoar.test.com"
      ],
      "DoNotTrackUserClicks": false,
      "EnableForInternalSenders": false,
      "EnableOrganizationBranding": false,
      "EnableSafeLinksForTeams": false,
      "ExchangeObjectId": "5796cea3-cfdb-4a99-9956-bf62209118a6",
      "ExchangeVersion": "0.20 (15.0.0.0)",
      "ExcludedUrls": [
        "www.test.com",
        "https://xsoar.test.com"
      ],
      "Guid": "5796cea3-cfdb-4a99-9956-bf62209118a6",
      "Id": "xsoartest",
      "Identity": "xsoartest",
      "IsBuiltInProtection": false,
      "IsDefault": false,
      "IsEnabled": true,
      "IsValid": true,
      "LocalizedNotificationTextList": [],
      "Name": "xsoartest",
      "ObjectCategory": "EURPR07A123.PROD.OUTLOOK.COM/Configuration/Schema/ms-Exch-Smart-Links-Protection-Config",
      "ObjectClass": [
        "top",
        "msExchSmartLinksProtectionConfig"
      ],
      "ObjectState": "Unchanged",
      "OrganizationId": "EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration",
      "OrganizationalUnitRoot": "xsoartest.onmicrosoft.com",
      "OriginatingServer": "AM7PR07A05DC123.EURPR07A123.PROD.OUTLOOK.COM",
      "PSComputerName": "outlook.office365.com",
      "PSShowComputerName": false,
      "RecommendedPolicyType": "Custom",
      "RunspaceId": "8501abb8-6d7c-45ca-bc0d-4c260d68d248",
      "ScanUrls": false,
      "TrackClicks": true,
      "WhenChanged": "2021-10-21T12:49:09+00:00",
      "WhenChangedUTC": "2021-10-21T12:49:09Z",
      "WhenCreated": "2021-10-21T12:49:03+00:00",
      "WhenCreatedUTC": "2021-10-21T12:49:03Z",
      "WhiteListedUrls": "www.test.com,https://xsoar.test.com"
    }
  ]
}

```

#### Human Readable Output
>### Results of o365-defender-safelinks-policy-create
>| AdminDisplayName | AllowClickThrough | CustomNotificationText | DeliverMessageAfterScan | DisableUrlRewrite | DistinguishedName | DoNotAllowClickThrough | DoNotRewriteUrls | DoNotTrackUserClicks | EnableForInternalSenders | EnableOrganizationBranding | EnableSafeLinksForTeams | ExchangeObjectId | ExchangeVersion | ExcludedUrls | Guid | Id | Identity | IsBuiltInProtection | IsDefault | IsEnabled | IsValid | LocalizedNotificationTextList | Name | ObjectCategory | ObjectClass | ObjectState | OrganizationalUnitRoot | OrganizationId | OriginatingServer | PSComputerName | PSShowComputerName | RecommendedPolicyType | RunspaceId | ScanUrls | TrackClicks | WhenChanged | WhenChangedUTC | WhenCreated | WhenCreatedUTC | WhiteListedUrls
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Few URL | true | Sorry, you cant click through this URL | false | false | CN=XSOAR Policy,CN=Safe Links,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM | false | | XSOAR Policy | EURPR07A123.PROD.OUTLOOK.COM/Configuration/Schema/ms-Exch-Smart-Links-Protection-Config | ["top","msExchSmartLinksProtectionConfig"] | Unchanged | xsoartest.onmicrosoft.com | EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration | AM7PR07A05DC123.EURPR07A123.PROD.OUTLOOK.COM | outlook.office365.com | false | Custom | {"value":"8501abb8-6d7c-45ca-bc0d-4c260d68d248","Guid":"8501abb8-6d7c-45ca-bc0d-4c260d68d248"} | false | true | {"value":"2021-10-21T12:49:09+00:00","DateTime":"Thursday, October 21, 2021 12:49:09 PM"} | {"value":"2021-10-21T12:49:09Z","DateTime":"Thursday, October 21, 2021 12:49:09 PM"} | {"value":"2021-10-21T12:49:03+00:00","DateTime":"Thursday, October 21, 2021 12:49:03 PM"} | {"value":"2021-10-21T12:49:03Z","DateTime":"Thursday, October 21, 2021 12:49:03 PM"} | www.test.com,https://xsoar.test.com


### o365-defender-safelinks-policy-update
***
Update a Safe Links policy.


#### Base Command

`o365-defender-safelinks-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A unique name for the Safe Links policy. | Required | 
| admin_display_name | The description for the policy. | Optional | 
| custom_notification_text | The custom notification text to show to users. | Optional | 
| deliver_message_after_scan | Whether to deliver email messages only after Safe Links scanning was completed. When true, messages that contain malicious links are not delivered. Default is false. Possible values are: true, false. | Optional | 
| do_not_allow_click_through | Whether to allow users to click through to the original URL on warning pages. Default is false. Possible values are: true, false. | Optional | 
| do_not_rewrite_urls | Comma-separated list of URLs that are not rewritten by Safe Links scanning. | Optional | 
| do_not_track_user_clicks | Whether to track user clicks related to Safe Links protection of links in email messages. Default is false. Possible values are: true, false. | Optional | 
| enable_for_internal_senders | Whether the Safe Links policy is applied to messages sent between internal senders and internal recipients within the same Exchange Online organization. Default is false. Possible values are: true, false. | Optional | 
| enable_organization_branding | Whether to display the organization's logo on Safe Links warning and notification pages. Default is false. Possible values are: true, false. | Optional | 
| enable_safe_links_for_teams | Whether to enable the Safe Links for Microsoft Teams. Default is false. Possible values are: true, false. | Optional | 
| is_enabled | Whether to enable Safe Links protection for email messages. Default is false. Possible values are: true, false. | Optional | 
| scan_urls | Whether to enable or disable real-time scanning of clicked links in email messages. Default is false. Possible values are: true, false. | Optional | 
| use_translated_notification_text | Whether to use Microsoft Translator to automatically localize the custom notification text that you specified with the CustomNotificationText parameter. Default is false. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365Defender.SafeLinks.AdminDisplayName | String | Policy description. | 
| O365Defender.SafeLinks.Policy.AllowClickThrough | Boolean | Whether users are allowed to click through the original URL. | 
| O365Defender.SafeLinks.Policy.CustomNotificationText | String | The customized notification text to show to users. | 
| O365Defender.SafeLinks.Policy.DeliverMessageAfterScan | Boolean | Whether the mail is delivered after Safe Links scanning was completed. | 
| O365Defender.SafeLinks.Policy.DisableUrlRewrite | Boolean | Whether URLs are rewritten \(wrapped\) in email messages. | 
| O365Defender.SafeLinks.Policy.DistinguishedName | String | Policy distinguished name \(DN\). | 
| O365Defender.SafeLinks.Policy.DoNotAllowClickThrough | Boolean | Whether users can click through the original URLs. | 
| O365Defender.SafeLinks.Policy.DoNotTrackUserClicks | Boolean | Whether user clicks are tracked. | 
| O365Defender.SafeLinks.Policy.DoNotRewriteUrls | Unknown | List of URLs that are not rewritten by Safe Links scanning. | 
| O365Defender.SafeLinks.Policy.EnableForInternalSenders | Boolean | Whether the Safe Links policy is applied to messages sent between internal senders and internal recipients within the same Exchange Online organization. | 
| O365Defender.SafeLinks.Policy.EnableOrganizationBranding | Boolean | whether the organization's logo is displayed on Safe Links warning and notification pages. | 
| O365Defender.SafeLinks.Policy.EnableSafeLinksForTeams | Boolean | Whether the Safe Links policy is enabled for Microsoft Teams. | 
| O365Defender.SafeLinks.Policy.ExchangeObjectId | String | Exchange object ID. | 
| O365Defender.SafeLinks.Policy.ExchangeVersion | String | The version of the Exchange server. | 
| O365Defender.SafeLinks.Policy.Guid | String | The GUID of the Safe Links policy. | 
| O365Defender.SafeLinks.Policy.Id | String | The ID of the Safe Links policy. | 
| O365Defender.SafeLinks.Policy.Identity | String | The identity of the Safe Links policy. | 
| O365Defender.SafeLinks.Policy.IsDefault | Boolean | Whether the Safe Links policy is the default policy. | 
| O365Defender.SafeLinks.Policy.IsEnabled | Boolean | Whether Safe Links protection is enabled for email messages. | 
| O365Defender.SafeLinks.Policy.IsValid | Boolean | Whether the Safe Links policy is valid. | 
| O365Defender.SafeLinks.Policy.Name | String | Policy name. | 
| O365Defender.SafeLinks.Policy.ObjectState | String | The Safe Links policy state. | 
| O365Defender.SafeLinks.Policy.OrganizationId | String | The organization ID. | 
| O365Defender.SafeLinks.Policy.ScanUrls | Boolean | Whether real-time scanning of clicked links in email messages is enabled. | 
| O365Defender.SafeLinks.Policy.WhenChanged | Date | The date and time the Safe Links policy was modified. Time format: YYYY-MM-DDThh:mm:ss\+00:00. | 
| O365Defender.SafeLinks.Policy.WhenChangedUTC | Date | The date and time \(in UTC\) the Safe Links policy was modified. Time format: YYYY-MM-DDTHH:MM:SSZ. | 
| O365Defender.SafeLinks.Policy.WhenCreated | Date | The date and time the Safe Links policy was created. Time format: YYYY-MM-DDThh:mm:ss\+00:00. | 
| O365Defender.SafeLinks.Policy.WhenCreatedUTC | Date | The date and time \(in UTC\) the Safe Links policy was created. Time format: YYYY-MM-DDTHH:MM:SSZ. | 


#### Command Example
```o365-defender-safelinks-policy-update name=xsoartest admin_display_name="Description for policy" do_not_allow_click_through=true```

#### Context Example
```json
{
  "O365Defender.SafeLinks.Policy(obj.Guid === val.Guid)": [
    {
      "AdminDisplayName": "Description for policy",
      "AllowClickThrough": true,
      "CustomNotificationText": "Sorry, you cant click through this URL",
      "DeliverMessageAfterScan": false,
      "DisableUrlRewrite": false,
      "DistinguishedName": "CN=xsoartest policy,CN=Safe Links,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM",
      "DoNotAllowClickThrough": false,
      "DoNotRewriteUrls": [
        "www.test.com",
        "https://xsoar.test.com"
      ],
      "DoNotTrackUserClicks": false,
      "EnableForInternalSenders": false,
      "EnableOrganizationBranding": false,
      "EnableSafeLinksForTeams": false,
      "ExchangeObjectId": "5796cea3-cfdb-4a99-9956-bf62209118a6",
      "ExchangeVersion": "0.20 (15.0.0.0)",
      "ExcludedUrls": [
        "www.test.com",
        "https://xsoar.test.com"
      ],
      "Guid": "5796cea3-cfdb-4a99-9956-bf62209118a6",
      "Id": "xsoartest policy",
      "Identity": "xsoartest policy",
      "IsBuiltInProtection": false,
      "IsDefault": false,
      "IsEnabled": true,
      "IsValid": true,
      "LocalizedNotificationTextList": [],
      "Name": "xsoartest",
      "ObjectCategory": "EURPR07A123.PROD.OUTLOOK.COM/Configuration/Schema/ms-Exch-Smart-Links-Protection-Config",
      "ObjectClass": [
        "top",
        "msExchSmartLinksProtectionConfig"
      ],
      "ObjectState": "Unchanged",
      "OrganizationId": "EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration",
      "OrganizationalUnitRoot": "xsoartest.onmicrosoft.com",
      "OriginatingServer": "AM7PR07A05DC123.EURPR07A123.PROD.OUTLOOK.COM",
      "PSComputerName": "outlook.office365.com",
      "PSShowComputerName": false,
      "RecommendedPolicyType": "Custom",
      "RunspaceId": "8501abb8-6d7c-45ca-bc0d-4c260d68d248",
      "ScanUrls": false,
      "TrackClicks": true,
      "WhenChanged": "2021-10-21T12:49:09+00:00",
      "WhenChangedUTC": "2021-10-21T12:49:09Z",
      "WhenCreated": "2021-10-21T12:49:03+00:00",
      "WhenCreatedUTC": "2021-10-21T12:49:03Z",
      "WhiteListedUrls": "www.test.com,https://xsoar.test.com"
    }
  ]
}

```

#### Human Readable Output
>### Results of o365-defender-safelinks-policy-list
>| AdminDisplayName | AllowClickThrough | CustomNotificationText | DeliverMessageAfterScan | DisableUrlRewrite | DistinguishedName | DoNotAllowClickThrough | DoNotRewriteUrls | DoNotTrackUserClicks | EnableForInternalSenders | EnableOrganizationBranding | EnableSafeLinksForTeams | ExchangeObjectId | ExchangeVersion | ExcludedUrls | Guid | Id | Identity | IsBuiltInProtection | IsDefault | IsEnabled | IsValid | LocalizedNotificationTextList | Name | ObjectCategory | ObjectClass | ObjectState | OrganizationalUnitRoot | OrganizationId | OriginatingServer | PSComputerName | PSShowComputerName | RecommendedPolicyType | RunspaceId | ScanUrls | TrackClicks | WhenChanged | WhenChangedUTC | WhenCreated | WhenCreatedUTC | WhiteListedUrls
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Few URL | true | Sorry, you cant click through this URL | false | false | CN=XSOAR Policy,CN=Safe Links,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM | false | | XSOAR Policy | EURPR07A123.PROD.OUTLOOK.COM/Configuration/Schema/ms-Exch-Smart-Links-Protection-Config | ["top","msExchSmartLinksProtectionConfig"] | Unchanged | xsoartest.onmicrosoft.com | EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration | AM7PR07A05DC123.EURPR07A123.PROD.OUTLOOK.COM | outlook.office365.com | false | Custom | {"value":"8501abb8-6d7c-45ca-bc0d-4c260d68d248","Guid":"8501abb8-6d7c-45ca-bc0d-4c260d68d248"} | false | true | {"value":"2021-10-21T12:49:09+00:00","DateTime":"Thursday, October 21, 2021 12:49:09 PM"} | {"value":"2021-10-21T12:49:09Z","DateTime":"Thursday, October 21, 2021 12:49:09 PM"} | {"value":"2021-10-21T12:49:03+00:00","DateTime":"Thursday, October 21, 2021 12:49:03 PM"} | {"value":"2021-10-21T12:49:03Z","DateTime":"Thursday, October 21, 2021 12:49:03 PM"} | www.test.com,https://xsoar.test.com



### o365-defender-safelinks-policy-remove
***
Remove a Safe Links policy.


#### Base Command

`o365-defender-safelinks-policy-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The identity of the Safe Links policy that you want to remove. Available identity fields of the policy are: Name, Distinguished name (DN), and GUID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !o365-defender-safelinks-policy-remove identity=XsoarTest ```

#### Human Readable Output

> #### Policy with Identity: XsoarTest was removed succesfully.

### o365-defender-safelinks-rule-list
***
List Safe Links rules in your cloud-based organization.


#### Base Command

`o365-defender-safelinks-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | The identity of the Safe Links rule that you want to view. Available identity fields are: Name, Distinguished name (DN), and GUID. | Optional | 
| state | The state of the rules. Possible values are: Enabled, Disabled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365Defender.SafeLinks.Rule.Comments | Unknown | Informative comments for the rule, such as what the rule is used for or how it has changed over time. The length of the comment cannot exceed 1024 characters. | 
| O365Defender.SafeLinks.Rule.Conditions | String | The rule condition. | 
| O365Defender.SafeLinks.Rule.Description | String | The description of the rule. | 
| O365Defender.SafeLinks.Rule.DistinguishedName | String | Rule distinguished name \(DN\). | 
| O365Defender.SafeLinks.Rule.ExceptIfRecipientDomainIs | Unknown | Recipients with email address in the specified domains are excluded. | 
| O365Defender.SafeLinks.Rule.ExceptIfSentTo | Unknown | Recipients to be excluded. | 
| O365Defender.SafeLinks.Rule.ExceptIfSentToMemberOf | Unknown | Recipients in these groups are excluded. | 
| O365Defender.SafeLinks.Rule.Exceptions | Unknown | Rule exceptions. | 
| O365Defender.SafeLinks.Rule.Guid | String | The GUID of the rule. | 
| O365Defender.SafeLinks.Rule.Identity | String | The identity of the Safe Links rule. | 
| O365Defender.SafeLinks.Rule.IsValid | Boolean | Whether the rule is valid. | 
| O365Defender.SafeLinks.Rule.Name | String | Rule name. | 
| O365Defender.SafeLinks.Rule.ObjectState | String | The state of the rule. | 
| O365Defender.SafeLinks.Rule.Priority | Number | The priority of the rule. | 
| O365Defender.SafeLinks.Rule.RecipientDomainIs | Unknown | List of domains that are included in the rule. | 
| O365Defender.SafeLinks.Rule.RuleVersion.Build | Number | Rule build number. | 
| O365Defender.SafeLinks.Rule.RunspaceId | String | Run space ID. | 
| O365Defender.SafeLinks.Rule.SafeLinksPolicy | String | The Safe Links policy that's associated with this Safe Links rule. | 
| O365Defender.SafeLinks.Rule.SentTo | Unknown | List of recipients included in the rule. | 
| O365Defender.SafeLinks.Rule.SentToMemberOf | Unknown | List of distribution groups, dynamic distribution groups, or mail-enabled security groups included in the rule. | 
| O365Defender.SafeLinks.Rule.State | String | The state of the rule. | 
| O365Defender.SafeLinks.Rule.WhenChanged | Date | The date and time the rule was modified. Time format: YYYY-MM-DDThh:mm:ss\+00:00. | 


#### Command Example
```!o365-defender-safelinks-rule-list```

#### Context Example
```json
{
  "O365Defender.SafeLinks.Rule(obj.Guid === val.Guid)": {
    "Comments": null,
    "Conditions": [
      "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SentToPredicate"
    ],
    "Description": "If the message:\r\n\tIs sent to 'xsoartest@xsoar.onmicrosoft.com'\r\nTake the following actions:\r\n\tApply safe links policy \"XSOAR Policy\".\r\n",
    "DistinguishedName": "CN=XSOAR Policy,CN=SafeLinksVersioned,CN=Rules,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM",
    "ExceptIfRecipientDomainIs": null,
    "ExceptIfSentTo": null,
    "ExceptIfSentToMemberOf": null,
    "Exceptions": null,
    "ExchangeVersion": "0.1 (8.0.535.0)",
    "Guid": "e5764de3-5495-4512-93f5-fe96d579fbd9",
    "Identity": "XSOAR Policy",
    "ImmutableId": "e5764de3-5495-4512-93f5-fe96d579fbd9",
    "IsValid": true,
    "Name": "XSOAR Policy",
    "ObjectState": "Unchanged",
    "OrganizationId": "EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration",
    "PSComputerName": "outlook.office365.com",
    "PSShowComputerName": false,
    "Priority": 2,
    "RecipientDomainIs": null,
    "RuleVersion": {
      "Build": 0,
      "Major": 14,
      "MajorRevision": 0,
      "Minor": 0,
      "MinorRevision": 0,
      "Revision": 0
    },
    "RunspaceId": "72b57693-0ddb-45b0-a44f-4d722a352635",
    "SafeLinksPolicy": "XSOAR Policy",
    "SentTo": [
      "xsoartest@xsoar.onmicrosoft.com"
    ],
    "SentToMemberOf": null,
    "State": "Enabled",
    "WhenChanged": "2021-10-21T12:49:40+00:00"
  }
}
 
```

#### Human Readable Output

>### Results of o365-defender-safelinks-rule-list
>| Comments | Conditions | Description | DistinguishedName | ExceptIfRecipientDomainIs | ExceptIfSentTo | ExceptIfSentToMemberOf | Exceptions | ExchangeVersion | Guid | Identity | ImmutableId | IsValid | Name | ObjectState | OrganizationId | Priority | PSComputerName | PSShowComputerName | RecipientDomainIs | RuleVersion | RunspaceId | SafeLinksPolicy | SentTo | SentToMemberOf | State | WhenChanged
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Changed recipients | "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SentToPredicate" | If the message: Is sent to 'xsoartest@xsoar.onmicrosoft.com'\ Take the following actions: Apply safe links policy "XSOAR Policy".\  | CN=XSOAR Policy,CN=SafeLinksVersioned,CN=Rules,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM |  |  |  |  | 0.1 (8.0.535.0) | {"value":"e5764de3-5495-4512-93f5-fe96d579fbd9","Guid":"e5764de3-5495-4512-93f5-fe96d579fbd9"} | XSOAR Policy | {"value":"e5764de3-5495-4512-93f5-fe96d579fbd9","Guid":"e5764de3-5495-4512-93f5-fe96d579fbd9"} | true | XSOAR Policy | Unchanged | EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration | 2 | outlook.office365.com | false |  | {"Major":14,"Minor":0,"Build":0,"Revision":0,"MajorRevision":0,"MinorRevision":0} | {"value":"72b57693-0ddb-45b0-a44f-4d722a352635","Guid":"72b57693-0ddb-45b0-a44f-4d722a352635"} | XSOAR Policy | "xsoartest@xsoar.onmicrosoft.com" |  | Enabled | {"value":"2021-10-21T12:49:40+00:00","DateTime":"Thursday, October 21, 2021 12:49:40 PM"}



### o365-defender-safelinks-rule-create
***
Create a Safe Links rule in your cloud-based organization.


#### Base Command

`o365-defender-safelinks-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A unique name for the Safe Links rule. | Required | 
| safe_links_policy | The Safe Links policy to associate with this Safe Links rule. | Required | 
| comments | An informative comment for the rule, such as what the rule is used for or how it has changed over time. The length of the comment cannot exceed 1024 characters. | Optional | 
| enabled | Whether the rule is enabled. Possible values are: true, false. | Optional | 
| except_if_recipient_domain_is | A comma-separated list of exceptions of recipients with email address in the specified domains. | Optional | 
| except_if_sent_to | A comma-separated list of exceptions of recipients in messages. | Optional | 
| except_if_sent_to_member_of | A comma-separated list of exceptions of messages sent to members of groups. | Optional | 
| priority | The priority value for the rule to determines the order of rule processing. A lower integer value indicates a higher priority. The value 0 is the highest priority. Rules cannot have the same priority value. | Optional | 
| recipient_domain_is | A comma-separated list of recipients with email address in the specified domains. | Optional | 
| sent_to | A comma-separated list of recipients in messages. You can use any value that uniquely identifies the recipient. | Optional | 
| sent_to_member_of | A comma-separated list of messages sent to members of distribution groups, dynamic distribution groups, or mail-enabled security groups. You can use any value that uniquely identifies the group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365Defender.SafeLinks.Rule.Comments | Unknown | Informative comments for the rule, such as what the rule is used for or how it has changed over time. The length of the comment cannot exceed 1024 characters. | 
| O365Defender.SafeLinks.Rule.Conditions | String | The rule condition. | 
| O365Defender.SafeLinks.Rule.Description | String | The description of the rule. | 
| O365Defender.SafeLinks.Rule.DistinguishedName | String | Rule distinguished name \(DN\). | 
| O365Defender.SafeLinks.Rule.ExceptIfRecipientDomainIs | Unknown | Recipients with an email address in the specified domains are excluded. | 
| O365Defender.SafeLinks.Rule.ExceptIfSentTo | Unknown | Recipients to be excluded. | 
| O365Defender.SafeLinks.Rule.ExceptIfSentToMemberOf | Unknown | Recipients in these groups are excluded. | 
| O365Defender.SafeLinks.Rule.Exceptions | Unknown | Rule exceptions. | 
| O365Defender.SafeLinks.Rule.Guid | String | The GUID of the rule. | 
| O365Defender.SafeLinks.Rule.Identity | String | The identity of the Safe Links rule. | 
| O365Defender.SafeLinks.Rule.IsValid | Boolean | Whether the rule is valid. | 
| O365Defender.SafeLinks.Rule.Name | String | Rule name. | 
| O365Defender.SafeLinks.Rule.ObjectState | String | The state of the rule. | 
| O365Defender.SafeLinks.Rule.Priority | Number | The priority of the rule. | 
| O365Defender.SafeLinks.Rule.RecipientDomainIs | Unknown | List of domains that are included in the rule. | 
| O365Defender.SafeLinks.Rule.RuleVersion.Build | Number | Rule build number. | 
| O365Defender.SafeLinks.Rule.RunspaceId | String | Run space ID. | 
| O365Defender.SafeLinks.Rule.SafeLinksPolicy | String | The Safe Links policy that's associated with this Safe Links rule. | 
| O365Defender.SafeLinks.Rule.SentTo | Unknown | List of recipients included in the rule. | 
| O365Defender.SafeLinks.Rule.SentToMemberOf | Unknown | List of distribution groups, dynamic distribution groups, or mail-enabled security groups included in the rule. | 
| O365Defender.SafeLinks.Rule.State | String | The state of the rule. | 
| O365Defender.SafeLinks.Rule.WhenChanged | Date | The date and time the rule was modified. Time format: YYYY-MM-DDThh:mm:ss\+00:00. | 


#### Command Example
```!o365-defender-safelinks-rule-create name="xsoartest rule" safe_links_policy="xsoartest policy" enabled=true  sent_to=xsoartest@xsoar.onmicrosoft.com```

#### Context Example
```json
{
  "O365Defender.SafeLinks.Rule(obj.Guid === val.Guid)": {
    "Comments": null,
    "Conditions": [
      "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SentToPredicate"
    ],
    "Description": "If the message:\r\n\tIs sent to 'xsoartest@xsoar.onmicrosoft.com'\r\nTake the following actions:\r\n\tApply safe links policy \"xsoartest policy"\".\r\n",
    "DistinguishedName": "CN=xsoartest rule,CN=SafeLinksVersioned,CN=Rules,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM",
    "ExceptIfRecipientDomainIs": null,
    "ExceptIfSentTo": null,
    "ExceptIfSentToMemberOf": null,
    "Exceptions": null,
    "ExchangeVersion": "0.1 (8.0.535.0)",
    "Guid": "e5764de3-5495-4512-93f5-fe96d579fbd9",
    "Identity": "XSOAR Policy",
    "ImmutableId": "e5764de3-5495-4512-93f5-fe96d579fbd9",
    "IsValid": true,
    "Name": "XSOAR Policy",
    "ObjectState": "Unchanged",
    "OrganizationId": "EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration",
    "PSComputerName": "outlook.office365.com",
    "PSShowComputerName": false,
    "Priority": 2,
    "RecipientDomainIs": null,
    "RuleVersion": {
      "Build": 0,
      "Major": 14,
      "MajorRevision": 0,
      "Minor": 0,
      "MinorRevision": 0,
      "Revision": 0
    },
    "RunspaceId": "72b57693-0ddb-45b0-a44f-4d722a352635",
    "SafeLinksPolicy": "xsoartest policy",
    "SentTo": [
      "xsoartest@xsoar.onmicrosoft.com"
    ],
    "SentToMemberOf": null,
    "State": "Enabled",
    "WhenChanged": "2021-10-21T12:49:40+00:00"
  }
}
 
```

#### Human Readable Output
>### Results of o365-defender-safelinks-rule-create
>| Comments | Conditions | Description | DistinguishedName | ExceptIfRecipientDomainIs | ExceptIfSentTo | ExceptIfSentToMemberOf | Exceptions | ExchangeVersion | Guid | Identity | ImmutableId | IsValid | Name | ObjectState | OrganizationId | Priority | PSComputerName | PSShowComputerName | RecipientDomainIs | RuleVersion | RunspaceId | SafeLinksPolicy | SentTo | SentToMemberOf | State | WhenChanged
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Changed recipients | "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SentToPredicate" | If the message: Is sent to 'xsoartest@xsoar.onmicrosoft.com'\ Take the following actions: Apply safe links policy "XSOAR Policy".\  | CN=XSOAR Policy,CN=SafeLinksVersioned,CN=Rules,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM |  |  |  |  | 0.1 (8.0.535.0) | {"value":"e5764de3-5495-4512-93f5-fe96d579fbd9","Guid":"e5764de3-5495-4512-93f5-fe96d579fbd9"} | XSOAR Policy | {"value":"e5764de3-5495-4512-93f5-fe96d579fbd9","Guid":"e5764de3-5495-4512-93f5-fe96d579fbd9"} | true | XSOAR Policy | Unchanged | EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration | 2 | outlook.office365.com | false |  | {"Major":14,"Minor":0,"Build":0,"Revision":0,"MajorRevision":0,"MinorRevision":0} | {"value":"72b57693-0ddb-45b0-a44f-4d722a352635","Guid":"72b57693-0ddb-45b0-a44f-4d722a352635"} | XSOAR Policy | "xsoartest@xsoar.onmicrosoft.com" |  | Enabled | {"value":"2021-10-21T12:49:40+00:00","DateTime":"Thursday, October 21, 2021 12:49:40 PM"}



### o365-defender-safelinks-rule-update
***
Update a given Safe Links rule.


#### Base Command

`o365-defender-safelinks-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A unique name for the Safe Links rule. | Required | 
| safe_links_policy | The Safe Links policy to associate with this Safe Links rule. | Required | 
| comments | An informative comment for the rule, such as what the rule is used for or how it has changed over time. The length of the comment cannot exceed 1024 characters. | Optional | 
| enabled | Whether the rule is enabled. Possible values are: true, false. | Optional | 
| except_if_recipient_domain_is | A comma-separated list of exceptions of recipients with an email address in the specified domains. | Optional | 
| except_if_sent_to | A comma-separated list of exceptions of recipients in messages. | Optional | 
| except_if_sent_to_member_of | A comma-separated list of exceptions of messages sent to members of groups. | Optional | 
| priority | The priority value for the rule to determines the order of rule processing. A lower integer value indicates a higher priority. The value 0 is the highest priority. Rules cannot have the same priority value. | Optional | 
| recipient_domain_is | A comma-separated list of recipients with an email address in the specified domains. | Optional | 
| sent_to | A comma-separated list of recipients in messages. You can use any value that uniquely identifies the recipient. | Optional | 
| sent_to_member_of | A comma-separated list of messages sent to members of distribution groups, dynamic distribution groups, or mail-enabled security groups. You can use any value that uniquely identifies the group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365Defender.SafeLinks.Rule.Comments | Unknown | Informative comments for the rule, such as what the rule is used for or how it has changed over time. The length of the comment cannot exceed 1024 characters. | 
| O365Defender.SafeLinks.Rule.Conditions | String | The rule condition. | 
| O365Defender.SafeLinks.Rule.Description | String | The description of the rule. | 
| O365Defender.SafeLinks.Rule.DistinguishedName | String | Rule distinguished name \(DN\). | 
| O365Defender.SafeLinks.Rule.ExceptIfRecipientDomainIs | Unknown | Recipients with email address in the specified domains are excluded. | 
| O365Defender.SafeLinks.Rule.ExceptIfSentTo | Unknown | Recipients to be excluded. | 
| O365Defender.SafeLinks.Rule.ExceptIfSentToMemberOf | Unknown | Recipients in these groups are excluded. | 
| O365Defender.SafeLinks.Rule.Exceptions | Unknown | Rule exceptions. | 
| O365Defender.SafeLinks.Rule.Guid | String | The GUID of the rule. | 
| O365Defender.SafeLinks.Rule.Identity | String | The identity of the Safe Links rule. | 
| O365Defender.SafeLinks.Rule.IsValid | Boolean | Whether the rule is valid. | 
| O365Defender.SafeLinks.Rule.Name | String | Rule name. | 
| O365Defender.SafeLinks.Rule.ObjectState | String | The state of the rule. | 
| O365Defender.SafeLinks.Rule.Priority | Number | The priority of the rule. | 
| O365Defender.SafeLinks.Rule.RecipientDomainIs | Unknown | List of domains that are included in the rule. | 
| O365Defender.SafeLinks.Rule.RuleVersion.Build | Number | Rule build number. | 
| O365Defender.SafeLinks.Rule.RunspaceId | String | Run space ID. | 
| O365Defender.SafeLinks.Rule.SafeLinksPolicy | String | The Safe Links policy that's associated with this Safe Links rule. | 
| O365Defender.SafeLinks.Rule.SentTo | Unknown | List of recipients included in the rule. | 
| O365Defender.SafeLinks.Rule.SentToMemberOf | Unknown | List of distribution groups, dynamic distribution groups, or mail-enabled security groups included in the rule. | 
| O365Defender.SafeLinks.Rule.State | String | The state of the rule. | 
| O365Defender.SafeLinks.Rule.WhenChanged | Date | The date and time the rule was modified. Time format: YYYY-MM-DDThh:mm:ss\+00:00. | 


#### Command Example
```!o365-defender-safelinks-rule-update name=XSOAR Rule safe_links_policy=XSOAR Policy comments="Description of the updated rule" ```
#### Context Example
```json
{
  "O365Defender.SafeLinks.Rule(obj.Guid === val.Guid)": {
    "Comments": "Description of the updated rule",
    "Conditions": [
      "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SentToPredicate"
    ],
    "Description": "If the message:\r\n\tIs sent to 'xsoartest@xsoar.onmicrosoft.com'\r\nTake the following actions:\r\n\tApply safe links policy \"XSOAR Policy\".\r\n",
    "DistinguishedName": "CN=XSOAR Policy,CN=SafeLinksVersioned,CN=Rules,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM",
    "ExceptIfRecipientDomainIs": null,
    "ExceptIfSentTo": null,
    "ExceptIfSentToMemberOf": null,
    "Exceptions": null,
    "ExchangeVersion": "0.1 (8.0.535.0)",
    "Guid": "e5764de3-5495-4512-93f5-fe96d579fbd9",
    "Identity": "XSOAR Policy",
    "ImmutableId": "e5764de3-5495-4512-93f5-fe96d579fbd9",
    "IsValid": true,
    "Name": "XSOAR Rule",
    "ObjectState": "Unchanged",
    "OrganizationId": "EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration",
    "PSComputerName": "outlook.office365.com",
    "PSShowComputerName": false,
    "Priority": 2,
    "RecipientDomainIs": null,
    "RuleVersion": {
      "Build": 0,
      "Major": 14,
      "MajorRevision": 0,
      "Minor": 0,
      "MinorRevision": 0,
      "Revision": 0
    },
    "RunspaceId": "72b57693-0ddb-45b0-a44f-4d722a352635",
    "SafeLinksPolicy": "XSOAR Policy",
    "SentTo": [
      "xsoartest@xsoar.onmicrosoft.com"
    ],
    "SentToMemberOf": null,
    "State": "Enabled",
    "WhenChanged": "2021-10-21T12:49:40+00:00"
  }
}
 
```

#### Human Readable Output
>### Results of o365-defender-safelinks-rule-update
>| Comments | Conditions | Description | DistinguishedName | ExceptIfRecipientDomainIs | ExceptIfSentTo | ExceptIfSentToMemberOf | Exceptions | ExchangeVersion | Guid | Identity | ImmutableId | IsValid | Name | ObjectState | OrganizationId | Priority | PSComputerName | PSShowComputerName | RecipientDomainIs | RuleVersion | RunspaceId | SafeLinksPolicy | SentTo | SentToMemberOf | State | WhenChanged
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Changed recipients | "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SentToPredicate" | If the message: Is sent to 'xsoartest@xsoar.onmicrosoft.com'\ Take the following actions: Apply safe links policy "XSOAR Policy".\  | CN=XSOAR Policy,CN=SafeLinksVersioned,CN=Rules,CN=Transport Settings,CN=Configuration,CN=xsoartest.onmicrosoft.com,CN=ConfigurationUnits,DC=EURPR07A123,DC=PROD,DC=OUTLOOK,DC=COM |  |  |  |  | 0.1 (8.0.535.0) | {"value":"e5764de3-5495-4512-93f5-fe96d579fbd9","Guid":"e5764de3-5495-4512-93f5-fe96d579fbd9"} | XSOAR Policy | {"value":"e5764de3-5495-4512-93f5-fe96d579fbd9","Guid":"e5764de3-5495-4512-93f5-fe96d579fbd9"} | true | XSOAR Policy | Unchanged | EURPR07A123.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/xsoartest.onmicrosoft.com - EURPR07A123.PROD.OUTLOOK.COM/ConfigurationUnits/xsoartest.onmicrosoft.com/Configuration | 2 | outlook.office365.com | false |  | {"Major":14,"Minor":0,"Build":0,"Revision":0,"MajorRevision":0,"MinorRevision":0} | {"value":"72b57693-0ddb-45b0-a44f-4d722a352635","Guid":"72b57693-0ddb-45b0-a44f-4d722a352635"} | XSOAR Policy | "xsoartest@xsoar.onmicrosoft.com" |  | Enabled | {"value":"2021-10-21T12:49:40+00:00","DateTime":"Thursday, October 21, 2021 12:49:40 PM"}

### o365-defender-safelinks-detailed-report-get
***
Get detailed information about Safe Links results for the last 7 days. Yesterday is the most recent date that you can specify.


#### Base Command

`o365-defender-safelinks-detailed-report-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start date of the date range in MM-DD-YYYY format.Yesterday is the most recent date that you can specify. You can't specify a date that's older than 7 days. Possible values are: . | Required | 
| end_date | End date of the date range in MM-DD-YYYY format.Yesterday is the most recent date that you can specify. You can't specify a date that's older than 7 days. Possible values are: . | Required | 
| domain |  filters the results by the domain in the URL. Possible values are: . | Optional | 
| app_names |  filters the results by the app where the link was found. You can enter multiple values separated by commas e.g "Value1,Value2,...ValueN". Possible values are: Email Client, OfficeDocs, Teams. | Optional | 
| action | filters the results by action. You can enter multiple values separated by commas e.g Value1,Value2,...ValueN. Possible values are: Allowed, Blocked, ClickedDuringScan, ClickedEvenBlocked, Scanning, TenantAllowed, TenantBlocked, TenantBlockedAndClickedThrough. | Optional | 
| recipient_address |  filters the results by the recipient's email address. Possible values are: . | Optional | 
| page | Page number of the results you want to view. Valid input for this parameter is an integer between 1 and 1000. The default value is 1. Possible values are: . | Optional | 
| page_size | Specifies the maximum number of entries per page. Valid input for this parameter is an integer between 1 and 5000. The default value is 1000. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365Defender.SafeLinks.DetailedReport.Data.ClickTime | Date | Time the url was clicked. | 
| O365Defender.SafeLinks.DetailedReport.Data.InternalMessageId | String | Internal message id. | 
| O365Defender.SafeLinks.DetailedReport.Data.ClientMessageId | String | Client message id. | 
| O365Defender.SafeLinks.DetailedReport.Data.SenderAddress | String | Sender of the email with the clicked URL. | 
| O365Defender.SafeLinks.DetailedReport.Data.RecipientAddress | String | Receiver of the email with the clicked URL. | 
| O365Defender.SafeLinks.DetailedReport.Data.Url | String | Clicked URL. | 
| O365Defender.SafeLinks.DetailedReport.Data.UrlDomain | String | Domain of th clicked URL. | 
| O365Defender.SafeLinks.DetailedReport.Data.Action | String | Action type. | 
| O365Defender.SafeLinks.DetailedReport.Data.AppName | String | App where the link was found. | 
| O365Defender.SafeLinks.DetailedReport.Data.SourceId | Unknown | Source id. | 
| O365Defender.SafeLinks.DetailedReport.Data.Organization | String | Organization. | 
| O365Defender.SafeLinks.DetailedReport.Data.DetectedBy | Unknown |  | 
| O365Defender.SafeLinks.DetailedReport.Data.UrlType | Unknown |  | 
| O365Defender.SafeLinks.DetailedReport.Data.Flags | Number | 0: Allowed 1: Blocked 2: ClickedEvenBlocked 3: ClickedDuringScan | 
| O365Defender.SafeLinks.DetailedReport.ReportId | Number | The report id, unique for every run | 

#### Command example
```!o365-defender-safelinks-detailed-report-get end_date=08-01-2022 start_date=07-31-2022```
#### Context Example
```json
{
    "O365Defender": {
        "SafeLinks": {
            "DetailedReport": {
                "Data": [
                    {
                        "Action": "Allowed",
                        "AppName": "Email Client",
                        "ClickTime": "2022-08-01T10:12:49",
                        "ClientMessageId": null,
                        "DetectedBy": "ATP safe links",
                        "EndDate": "0001-01-01T00:00:00",
                        "Flags": 0,
                        "InternalMessageId": "dc6ebe31-e968-4cf8-a4b4-08da73a65b1c",
                        "Organization": "test.onmicrosoft.com",
                        "PSComputerName": "outlook.office365.com",
                        "PSShowComputerName": false,
                        "RecipientAddress": "test@test.onmicrosoft.com",
                        "RunspaceId": "93d2c78c-db42-41a0-b67c-5f72881b7338",
                        "SenderAddress": null,
                        "SourceId": null,
                        "StartDate": "0001-01-01T00:00:00",
                        "Url": "http://go.microsoft.com/",
                        "UrlDomain": "go.microsoft.com",
                        "UrlType": ""
                    }
                ],
                "ReportId": "93d2c78c-db42-41a0-b67c-5f72881b7338"
            }
        }
    }
}
```

#### Human Readable Output
### Results of o365-defender-safelinks-detailed-report-get
| Action | AppName | ClickTime | ClientMessageId | DetectedBy | EndDate | Flags | InternalMessageId | Organization | PSComputerName | PSShowComputerName | RecipientAddress | RunspaceId | SenderAddress | SourceId | StartDate | Url | UrlDomain | UrlType
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
| Allowed | Email Client | \{"value":"2022\-08\-01T10:12:49","DateTime":"Monday, August 1, 2022 10:12:49 AM"\} |  | ATP safe links | \{"value":"0001\-01\-01T00:00:00","DateTime":"Monday, January 1, 0001 12:00:00 AM"\} | 0 | \{"value":"dc6ebe31\-e968\-4cf8\-a4b4\-08da73a65b1c","Guid":"dc6ebe31\-e968\-4cf8\-a4b4\-08da73a65b1c"\} | test.onmicrosoft.com | outlook.office365.com | false | test@test.onmicrosoft.com | \{"value":"39cbdab4\-5b97\-4f20\-bb17\-b0d1848183a6","Guid":"39cbdab4\-5b97\-4f20\-bb17\-b0d1848183a6"\} |  |  | \{"value":"0001\-01\-01T00:00:00","DateTime":"Monday, January 1, 0001 12:00:00 AM"\} | http://go.microsoft.com/ | go.microsoft.com | 



### o365-defender-safelinks-aggregate-report-get
***
general information about Safe Links results for the last 90 days. Yesterday is the most recent date that you can specify.


#### Base Command

`o365-defender-safelinks-aggregate-report-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Start date of the date range in MM-DD-YYYY format.Yesterday is the most recent date that you can specify. You can't specify a date that's older than 90 days. Possible values are: . | Required | 
| end_date | End date of the date range in MM-DD-YYYY format.YYesterday is the most recent date that you can specify. You can't specify a date that's older than 90 days. Possible values are: . | Required | 
| app_names |  filters the results by the app where the link was found. You can enter multiple values separated by commas e.g "Value1,Value2,...ValueN". Possible values are: Email Client, OfficeDocs, Teams. | Optional | 
| action | filters the results by action. You can enter multiple values separated by commas e.g Value1,Value2,...ValueN. Possible values are: Allowed, Blocked, ClickedDuringScan, ClickedEvenBlocked, Scanning, TenantAllowed, TenantBlocked, TenantBlockedAndClickedThrough. | Optional | 
| summerize_by | Returns totals based on the values you specify. Summarizing reduces the amount of data that's retrieved for the report, and delivers the report faster. By default the summrize is by Action. Possible values are: Action, App. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365Defender.SafeLinks.AggregateReport.Data.App | String | App where the link was found. | 
| O365Defender.SafeLinks.AggregateReport.Data.Action | String | Action type. | 
| O365Defender.SafeLinks.AggregateReport.Data.MessageCount | Number | Number of messages with a link. | 
| O365Defender.SafeLinks.AggregateReport.Data.RecipientCount | Number | Number of recipients of the link. | 
| O365Defender.SafeLinks.AggregateReport.ReportId | Number | The report id, unique for every run | 

#### Command example
```!o365-defender-safelinks-aggregate-report-get end_date=08-01-2022 start_date=07-31-2022```
#### Context Example
```json
{
    "O365Defender": {
        "SafeLinks": {
            "AggregateReport": {
                "Data": [
                    {
                        "Action": "Allowed",
                        "App": "",
                        "EndDate": "0001-01-01T00:00:00",
                        "MessageCount": 0,
                        "PSComputerName": "outlook.office365.com",
                        "PSShowComputerName": false,
                        "RecipientCount": 0,
                        "RunspaceId": "e3633f6c-e9b5-4c9d-9acc-8f669b28a974",
                        "StartDate": "0001-01-01T00:00:00"
                    },
                    {
                        "Action": "TenantAllowed",
                        "App": "",
                        "EndDate": "0001-01-01T00:00:00",
                        "MessageCount": 0,
                        "PSComputerName": "outlook.office365.com",
                        "PSShowComputerName": false,
                        "RecipientCount": 0,
                        "RunspaceId": "e3633f6c-e9b5-4c9d-9acc-8f669b28a974",
                        "StartDate": "0001-01-01T00:00:00"
                    },
                    {
                        "Action": "Blocked",
                        "App": "",
                        "EndDate": "0001-01-01T00:00:00",
                        "MessageCount": 0,
                        "PSComputerName": "outlook.office365.com",
                        "PSShowComputerName": false,
                        "RecipientCount": 0,
                        "RunspaceId": "e3633f6c-e9b5-4c9d-9acc-8f669b28a974",
                        "StartDate": "0001-01-01T00:00:00"
                    },
                    {
                        "Action": "TenantBlocked",
                        "App": "",
                        "EndDate": "0001-01-01T00:00:00",
                        "MessageCount": 0,
                        "PSComputerName": "outlook.office365.com",
                        "PSShowComputerName": false,
                        "RecipientCount": 0,
                        "RunspaceId": "e3633f6c-e9b5-4c9d-9acc-8f669b28a974",
                        "StartDate": "0001-01-01T00:00:00"
                    },
                    {
                        "Action": "ClickedEvenBlocked",
                        "App": "",
                        "EndDate": "0001-01-01T00:00:00",
                        "MessageCount": 0,
                        "PSComputerName": "outlook.office365.com",
                        "PSShowComputerName": false,
                        "RecipientCount": 0,
                        "RunspaceId": "e3633f6c-e9b5-4c9d-9acc-8f669b28a974",
                        "StartDate": "0001-01-01T00:00:00"
                    },
                    {
                        "Action": "TenantBlockedAndClickedThrough",
                        "App": "",
                        "EndDate": "0001-01-01T00:00:00",
                        "MessageCount": 0,
                        "PSComputerName": "outlook.office365.com",
                        "PSShowComputerName": false,
                        "RecipientCount": 0,
                        "RunspaceId": "e3633f6c-e9b5-4c9d-9acc-8f669b28a974",
                        "StartDate": "0001-01-01T00:00:00"
                    },
                    {
                        "Action": "Scanning",
                        "App": "",
                        "EndDate": "0001-01-01T00:00:00",
                        "MessageCount": 0,
                        "PSComputerName": "outlook.office365.com",
                        "PSShowComputerName": false,
                        "RecipientCount": 0,
                        "RunspaceId": "e3633f6c-e9b5-4c9d-9acc-8f669b28a974",
                        "StartDate": "0001-01-01T00:00:00"
                    },
                    {
                        "Action": "ClickedDuringScan",
                        "App": "",
                        "EndDate": "0001-01-01T00:00:00",
                        "MessageCount": 0,
                        "PSComputerName": "outlook.office365.com",
                        "PSShowComputerName": false,
                        "RecipientCount": 0,
                        "RunspaceId": "e3633f6c-e9b5-4c9d-9acc-8f669b28a974",
                        "StartDate": "0001-01-01T00:00:00"
                    }
                ],
                "ReportId": "e3633f6c-e9b5-4c9d-9acc-8f669b28a974"
            }
        }
    }
}
```

#### Human Readable Output
### Results of o365-defender-safelinks-aggregate-report-get
| Action | App | EndDate | MessageCount | PSComputerName | PSShowComputerName | RecipientCount | RunspaceId | StartDate
| --- | --- | --- | --- | --- | --- | --- | --- | ---
| Allowed |  | \{"value":"0001\-01\-01T00:00:00","DateTime":"Monday, January 1, 0001 12:00:00 AM"\} | 0 | outlook.office365.com | false | 0 | \{"value":"0063bc64\-9230\-43a9\-91b3\-10829ec2801f","Guid":"0063bc64\-9230\-43a9\-91b3\-10829ec2801f"\} | \{"value":"0001\-01\-01T00:00:00","DateTime":"Monday, January 1, 0001 12:00:00 AM"\}

Known Limitations
----


#### Base Command

`o365-defender-safelinks-atp-policy-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365Defender.SafeLinks.AtpPolicy.Name | String | ATP policy name. | 
| O365Defender.SafeLinks.AtpPolicy.AdminDisplayName | String | ATP policy admin display name. | 
| O365Defender.SafeLinks.AtpPolicy.EnableATPForSPOTeamsODB | String | ATP policy enabled for SPOT teams. | 
| O365Defender.SafeLinks.AtpPolicy.AllowSafeDocsOpen | String | Whether the ATP policy allows safe docs to open. | 
| O365Defender.SafeLinks.AtpPolicy.EnableSafeDocs | String | Whether the ATP policy enables safe docs. | 
| O365Defender.SafeLinks.AtpPolicy.Identity | String | ATP policy ID. | 
| O365Defender.SafeLinks.AtpPolicy.IsValid | String | Is the ATP policy valid. | 
| O365Defender.SafeLinks.AtpPolicy.WhenCreatedUTC | String | When the ATP policy was created in UTC format. | 
| O365Defender.SafeLinks.AtpPolicy.WhenChangedUTC | String | When the ATP policy was changed in UTC format. | 

### o365-defender-safelinks-atp-policy-set
***
Set the ATP policy.


#### Base Command

`o365-defender-safelinks-atp-policy-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| allow_safe_docs_open | Whether users can click through and bypass the Protected View container even when Safe Documents identifies a file as malicious. Possible values are: true, false. | Optional | 
| enable_atp_spo_teams_odb | Enable or disable O365 Defender for SharePoint, OneDrive, and Microsoft Teams. Possible values are: true, false. | Optional | 
| enable_safe_docs | Enable or disable safe Documents in organizations with Microsoft 365 A5 or Microsoft 365 E5 Security licenses. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

* Safe Links does not work on mail-enabled public folders.
* Safe Links protection is available in the following locations:
    * Office 365 apps: Safe Links protection for Office 365 apps is available in supported desktop, mobile, and web apps. You configure Safe Links protection for Office 365 apps in the global setting that are outside of Safe Links policies. For instructions, see [Configure global settings for Safe Links settings in Microsoft Defender for Office 365](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/configure-global-settings-for-safe-links?view=o365-worldwide).
    * Microsoft Teams: Safe Links protection for links in Teams conversations, group chats, or from channels is also controlled by Safe Links policies. There is no default Safe Links policy, so to get the protection of Safe Links in Teams, you need to create one or more Safe Links policies.
    * Email messages: Safe Links protection for links in email messages is controlled by Safe Links policies. There is no default Safe Links policy, so to get the protection of Safe Links in email messages, you need to create one or more Safe Links policies.
* Allow up to 30 minutes for a new or updated policy to be applied.
* Organization - be sure to use an `.onmicrosoft.com` domain in the Organization parameter value. Otherwise, you might encounter cryptic permission issues when you run commands in the app context.