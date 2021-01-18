BitcoinAbuse.com is a public database of bitcoin addresses used by hackers and criminals.
Supported Cortex XSOAR versions: 5.5.0 and later.

## Get Your API Key
In order to use Bitcoin Abuse service, you need to get your API key.
The API key is free and can be achieved by doing the following:
1. Navigate to https://www.bitcoinabuse.com and click on "Register" on top right corner of your screen.
2. Fill in your details (Name, Email, Password, etc...)
3. After your account have been set, go to Settings, and click on "API" section.
4. Give your API token a name, and click on "Create", a screen containing your generated API key
will appear.

## Configure BitcoinAbuse on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for BitcoinAbuse.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | feed | Fetch indicators | False |
    | api_key | API Key | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | initial_fetch_interval | First Fetch Time | True |
    | feedReputation | Indicator Reputation | False |
    | feedReliability | Source Reliability | True |
    | feedExpirationPolicy |  | False |
    | tlp_color | Traffic Light Protocol Color | False |
    | feedFetchInterval | Feed Fetch Interval | False |
    | feedExpirationInterval |  | False |
    | feedBypassExclusionList | Bypass exclusion list | False |
    | feedTags | Tags | False |

4. Click **Test** to validate the URLs, token, and connection.
## Fetching indicators
#### Initial Fetch
When configuring an integration instance, you will be required to enter the first fetch parameter which will set the timeframe to pull Indicators in the first fetch, Two options are available:

- 30 Days - Indicators recorded in the last 30 days (updates every Sunday between 2am-3am UTC.)
- Forever - All recorded indicators (updates every 15th of the month between 2am-3am UTC.)


Note: 
- Whenever Forever is selected, in order to bring as much data as possible in the first fetch, we merge the Forever CSV together the 30 Days CSV file to avoid missing as much data as possible.
- Restrictions will be that any data reported between Sunday  (after 30 Days file update) to the day of the first fetch
will not be fetched

#### Each fetch after the initial fetch 
Each fetch after the initial fetch will return indicators reported on the previous day (updates once a day between 2am-3am UTC). Therefore, fetching more than once a day will not have any effect.


## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bitcoinabuse-report-address
***
Reports an abuser to Bitcoin Abuse service. 'abuse_type_other' field is required when 'abuse_type' is other


#### Base Command

`bitcoinabuse-report-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | Address of the abuser. | Required | 
| abuser | Information about the abuser. | Required | 
| description | Description of the abuse. | Optional | 
| abuse_type | Type of abuse. The "abuse_type_other" field is required when the value of the "abuse_type" field is "other". Possible values are "ransomware", "darknet market", "bitcoin tumber", "blackmail scam", "sextortion", and "other". Possible values are: ransomware, darknet market, bitcoin tumbler, blackmail scam, sextortion, other. | Required | 
| abuse_type_other | Description of the abuse type. The "abuse_type_other" field is required when the value of the "abuse_type" field is "other". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!bitcoinabuse-report-address address=abcde12345 abuser=abuser@abuse.net abuse_type="bitcoin tumbler" description="this is a description of the abuse"```


#### Human Readable Output

>Bitcoin address abcde12345 by abuse bitcoin user abuser@abuse.net was reported to BitcoinAbuse API

### bitcoinabuse-get-indicators
***
Gets indicators from the feed.


#### Base Command

`bitcoinabuse-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 50. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!bitcoinabuse-get-indicators limit=5```

#### Context Example
```json
{}
```

#### Human Readable Output

>### Indicators
>|value|type|fields|
>|---|---|---|
>| bitcoin:14Y7Cojvd6DyPtkZSvrrKyUhXkjjEHDjya | Cryptocurrency Address | Value: bitcoin:14Y7Cojvd6DyPtkZSvrrKyUhXkjjEHDjya<br/>rawaddress: 14Y7Cojvd6DyPtkZSvrrKyUhXkjjEHDjya<br/>countryname: Belarus<br/>creationdate: 2021-01-17T00:27:49.000000Z<br/>description: Здравствуйте!<br/><br/>Думаю Вас не очень обрадует то, что вы увидите дальше.<br/>Делов вот в чём: через ваш роутер я подключился к вашей сети. Далее Я нашёл брешь в операционной системе вашего компьютера и залил свой код. Во всём виновата ваша любовь к жёсткой порнушке.<br/>Этот код дал мне абсолютные права над вашим компьютером и периферией.<br/>Это ознaчaет, что я могу видеть вcе нa вaшем экрaне, включить кaмеру и микрoфон, но вы нe знaетe oб этом.<br/>Все ваши контакты, переписки для меня тоже видны. В общем вы для меня открытая книга, так сказать.<br/><br/>И вот уже почти три месяца к ряду я собираю всякие интересности о вас. Честно говоря не ожидал такого от вас. Потом меня посетила одна мысль.<br/>В редакторе я объеденил две записи, а именно: слева показывается как вы развлекаетесь сами с собой разными способами, а справа идёт тот изрващенский контетнт , который вы просматривали.<br/>Всего пара кликов мыши и это чудо отправится по всем емейлам, друзьям и знакомым в соцсетях.<br/><br/>Еcли вы хoтите это предотвратить, тo вам нужно перевести на мой счёт 702 USD. Уверен вы слышали о биткойнах, вот в них и переводите.<br/>Но если вы не знаете как пополнить такой кошелёк воспользуйтесь любым поисковиком типа гугла или яндекса. В этом нет ничего сложного.<br/>Перевод делайте на этот кошелек: 14Y7Cojvd6DyPtkZSvrrKyUhXkjjEHDjya<br/><br/>Пocле пoлучения оплaты я всё удaлю и вы никогдa меня бoльше не уcлышите. На всё про всё у вас двое суток.<br/>Процесс был запущен после того,Как вы открыли это сообщение. ID счетчика - 660619032<br/>Писать в ответ смысла нет - адрес отправителя состоит из произвольных данных.<br/>Не советую куда-либо обращаться.<br/>Если я увижу, что вы с кем то поделились нашим маленьким секретом - в этом случае, как я писал выше, все ваши контакты получат по копии записи с вами.<br/>abusetype: blackmail scam<br/>tags: <br/>reportscount: 8<br/>cryptocurrencyaddresstype: bitcoin |
>| bitcoin:1MfhfDZdv2QXmBBZMom5ZnZzp8VVrJUENw | Cryptocurrency Address | Value: bitcoin:1MfhfDZdv2QXmBBZMom5ZnZzp8VVrJUENw<br/>rawaddress: 1MfhfDZdv2QXmBBZMom5ZnZzp8VVrJUENw<br/>countryname: Australia<br/>creationdate: 2021-01-17T00:30:36.000000Z<br/>description: I know ******** is one of your password on day of hack..<br/><br/>Lets get directly to the point.<br/>Not one person has paid me to check about you.<br/><br/>You do not know me and you're probably thinking why you are getting this email?<br/>in fact, i actually placed a malware on the adult vids (adult porn) website and you know what, you visited this site to experience fun (you know what i mean).<br/>When you were viewing videos, your browser started out operating as a RDP having a key logger which provided me with accessibility to your display and web cam.<br/><br/><br/>immediately after that, my malware obtained every one of your contacts from your Messenger, FB, as well as email account.<br/><br/><br/>after that i created a double-screen video. 1st part shows the video you were viewing (you have a nice taste omg), and 2nd part displays the recording of your cam, and its you.<br/>Best solution would be to pay me $2763.<br/><br/><br/>We are going to refer to it as a donation. in this situation, i most certainly will without delay remove your video.<br/><br/><br/><br/>Bitcoin address: 1MfhfDZdv2QXmBBZMom5ZnZzp8VVrJUENw<br/><br/>[case SeNSiTiVe, copy & paste it]<br/><br/><br/>You could go on your life like this never happened and you will not ever hear back again from me.<br/><br/><br/>You'll make the payment via Bitcoin (if you do not know this, search 'how to buy bitcoin' in Google).<br/>if you are planning on going to the law, surely, this e-mail can not be traced back to me, because it's hacked too.<br/>I have taken care of my actions. i am not looking to ask you for a lot, i simply want to be paid.<br/>if i do not receive the bitcoin;, i definitely will send out your video recording to all of your contacts including friends and family, co-workers, and so on.<br/>Nevertheless, if i do get paid, i will destroy the recording immediately.<br/>If you need proof, reply with Yeah then i will send out your video recording to your 8 friends.<br/>it's a nonnegotiable offer and thus please don't waste mine time & yours by replying to this message.<br/>abusetype: ransomware<br/>tags: <br/>reportscount: 1<br/>cryptocurrencyaddresstype: bitcoin |
>| bitcoin:19tZgzcS4arg9xKb5FRx18YDupoTBj9gh4 | Cryptocurrency Address | Value: bitcoin:19tZgzcS4arg9xKb5FRx18YDupoTBj9gh4<br/>rawaddress: 19tZgzcS4arg9xKb5FRx18YDupoTBj9gh4<br/>creationdate: 2021-01-17T00:34:35.000000Z<br/>description: https://www.youtube.com/channel/UCGR9JcaZAW7eKw6cpMHFn9A<br/>https://archive.is/jL73d<br/><br/>https://www.youtube.com/watch?v=F7q1Pj8h0NM&ab_channel=[Inc.Ethereum]<br/>https://archive.is/zIMhY<br/><br/>https://ethereumgive.us/<br/>https://archive.is/F7d9L<br/><br/>https://ethereumgive.us/eth<br/>https://archive.is/AJFPz<br/>0x0dee972Fad19F4eA48A4d9604Ac3Fc9F3B56b7E5<br/>https://archive.is/lpf2H<br/>0xa46c9e0B39e2FA395B8d209b39B6B43a101A8D53<br/><br/>https://ethereumgive.us/btc<br/>https://archive.is/p0kEh<br/>19ibsb1cTVXN7o9GgiR1vQErH9B3i6nZuZ<br/>https://archive.is/zgAf4<br/>19tZgzcS4arg9xKb5FRx18YDupoTBj9gh4<br/><br/>https://ethereumgive.us/xrp<br/>https://archive.is/1pFfC<br/>rDbc3vZGsJRLZCGUDeQRzY188WkvDDM2Un<br/>https://archive.is/AjfgL<br/>rUgMbBFpASc7ZGKCqprVhGNygSoBPpyVWg<br/>abusetype: other<br/>tags: <br/>reportscount: 1<br/>cryptocurrencyaddresstype: bitcoin |
>| bitcoin:19ibsb1cTVXN7o9GgiR1vQErH9B3i6nZuZ | Cryptocurrency Address | Value: bitcoin:19ibsb1cTVXN7o9GgiR1vQErH9B3i6nZuZ<br/>rawaddress: 19ibsb1cTVXN7o9GgiR1vQErH9B3i6nZuZ<br/>creationdate: 2021-01-17T00:34:51.000000Z<br/>description: https://www.youtube.com/channel/UCGR9JcaZAW7eKw6cpMHFn9A<br/>https://archive.is/jL73d<br/><br/>https://www.youtube.com/watch?v=F7q1Pj8h0NM&ab_channel=[Inc.Ethereum]<br/>https://archive.is/zIMhY<br/><br/>https://ethereumgive.us/<br/>https://archive.is/F7d9L<br/><br/>https://ethereumgive.us/eth<br/>https://archive.is/AJFPz<br/>0x0dee972Fad19F4eA48A4d9604Ac3Fc9F3B56b7E5<br/>https://archive.is/lpf2H<br/>0xa46c9e0B39e2FA395B8d209b39B6B43a101A8D53<br/><br/>https://ethereumgive.us/btc<br/>https://archive.is/p0kEh<br/>19ibsb1cTVXN7o9GgiR1vQErH9B3i6nZuZ<br/>https://archive.is/zgAf4<br/>19tZgzcS4arg9xKb5FRx18YDupoTBj9gh4<br/><br/>https://ethereumgive.us/xrp<br/>https://archive.is/1pFfC<br/>rDbc3vZGsJRLZCGUDeQRzY188WkvDDM2Un<br/>https://archive.is/AjfgL<br/>rUgMbBFpASc7ZGKCqprVhGNygSoBPpyVWg<br/>abusetype: other<br/>tags: <br/>reportscount: 1<br/>cryptocurrencyaddresstype: bitcoin |
>| bitcoin:14Y7Cojvd6DyPtkZSvrrKyUhXkjjEHDjya | Cryptocurrency Address | Value: bitcoin:14Y7Cojvd6DyPtkZSvrrKyUhXkjjEHDjya<br/>rawaddress: 14Y7Cojvd6DyPtkZSvrrKyUhXkjjEHDjya<br/>countryname: Russia<br/>creationdate: 2021-01-17T00:42:50.000000Z<br/>description: Здравствуйте!<br/><br/>Думаю Вас не очень обрадует то, что вы увидите дальше.<br/>Делов вот в чём: через ваш роутер я подключился к вашей сети. Далее Я нашёл брешь в операционной системе вашего компьютера и залил свой код. Во всём виновата ваша любовь к жёсткой порнушке.<br/>Этот код дал мне абсолютные права над вашим компьютером и периферией.<br/>Это ознaчaет, что я могу видеть вcе нa вaшем экрaне, включить кaмеру и микрoфон, но вы нe знaетe oб этом.<br/>Все ваши контакты, переписки для меня тоже видны. В общем вы для меня открытая книга, так сказать.<br/><br/>И вот уже почти три месяца к ряду я собираю всякие интересности о вас. Честно говоря не ожидал такого от вас. Потом меня посетила одна мысль.<br/>В редакторе я объеденил две записи, а именно: слева показывается как вы развлекаетесь сами с собой разными способами, а справа идёт тот изрващенский контетнт , который вы просматривали.<br/>Всего пара кликов мыши и это чудо отправится по всем емейлам, друзьям и знакомым в соцсетях.<br/><br/>Еcли вы хoтите это предотвратить, тo вам нужно перевести на мой счёт 704 USD. Уверен вы слышали о биткойнах, вот в них и переводите.<br/>Но если вы не знаете как пополнить такой кошелёк воспользуйтесь любым поисковиком типа гугла или яндекса. В этом нет ничего сложного.<br/>Перевод делайте на этот кошелек: 14Y7Cojvd6DyPtkZSvrrKyUhXkjjEHDjya<br/><br/>Пocле пoлучения оплaты я всё удaлю и вы никогдa меня бoльше не уcлышите. На всё про всё у вас двое суток.<br/>Процесс был запущен после того,Как вы открыли это сообщение. ID счетчика - 15035264<br/>Писать в ответ смысла нет - адрес отправителя состоит из произвольных данных.<br/>Не советую куда-либо обращаться.<br/>Если я увижу, что вы с кем то поделились нашим маленьким секретом - в этом случае, как я писал выше, все ваши контакты получат по копии записи с вами.<br/>abusetype: blackmail scam<br/>tags: <br/>reportscount: 8<br/>cryptocurrencyaddresstype: bitcoin |

