import pytest
import copy
import demistomock as demisto


incidents_list = [{'alert_name': 'Your organization was potentially targeted by a ransomware group', 'content': 'Poirier\xa0Sport\xa0Complex\xa0(PSLC)\xa0Arena\xa03\xa0Conversion\xa0–\xa0Phase\xa02,\xa0Coquitlam\xa0BC\xa0 \nCapilano\xa0University\xa0Library\xa0Reno\xa0&#x2F;\xa0Center\xa0for\xa0Student\xa0Success\xa0–\xa0Phase\xa02\xa0 \n@sixgill-start-highlight@Walmart@sixgill-end-highlight@\xa03042\xa0Kelowna\xa0Relay\nCity\xa0of\xa0Vancouver\xa02780\xa0East\xa0Broadway\nCompany:Traugott Building Contractors Inc.', 'date': '2021-11-08 06:01:05', 'id': '6188bd21017198385e228437', 'read': True, 'severity': 1, 'site': 'rw_everest', 'status': {'name': 'in_treatment', 'user': '60b604a048ce2cb294629a2d'}, 'threat_level': 'imminent', 'threats': ['Brand Protection', 'Data Leak'], 'title': 'Your organization was potentially targeted by a ransomware group', 'user_id': '5d233575f8db38787dbe24b6'}, {'alert_name': 'Gift Cards of {organization_name} are Sold on the Underground ', 'category': 'regular', 'content': 'New carded gift cards\nHi fellow friend and business dealer here I got any kind of gift cards you want and I carded by me. I can send it to your address or give you code.especially ..Amazon ,Gift Card,Walmart ,Gift Card,Ebay ,Gift Card,BestBuy ,Gift CardTarget ,Xbox Gift Card,Psn Gift Card,Nordstrom Gift Cardsand Nike Gift Cards  interested can contact me on  telegram...@kartel25', 'date': '2021-11-02 06:00:27', 'id': '6180d4011dbb8edcb496ec8b', 'lang': 'English', 'langcode': 'en', 'read': False, 'severity': 1, 'status': {'name': 'treatment_required', 'user': '604f58a6dc7c8a8437fd8154'}, 'sub_alerts': [{'aggregate_alert_id': 0, 'content': 'New carded gift cards\nHi fellow friend and business dealer here I got any kind of gift cards you want and I carded by me. I can send it to your address or give you code.especially ..Amazon ,Gift Card,Walmart ,Gift Card,Ebay ,Gift Card,BestBuy ,Gift CardTarget ,Xbox Gift Card,Psn Gift Card,Nordstrom Gift Cardsand Nike Gift Cards  interested can contact me on  telegram...@kartel25', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'forum_cardvilla'}, {'aggregate_alert_id': 1, 'content': 'Như tiêu đề e đang có 5k walmart gift code loại 5$ nguồn offer! \nBác nào cần liên hệ fb, icq, skype dưới avata nhé! \u200b', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'forum_mmo4me'}, {'aggregate_alert_id': 2, 'content': 'Would anyone be able to tell me where I can buy walmart gift cards? Not the ones issued by greendot, the ones with the 4 digit pin.', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'dread'}, {'aggregate_alert_id': 3, 'content': 'Quantity: 3000 Available / 0 Sold\nSeller Information orangstore44 ( 20 ) Ship From: United States Ship To: Worldwide \nMessage us before placing your order NB..Check our telegram well before sending us a message Download any of the fowolling below and add me using and of their username as beneath.. ....Wickr ID......... supplug ....TELEGRAM....... blink9888 ....Whatsapp #.... +1 (252) 368-6780 Amazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift.WU,PAYPA', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 4, 'content': 'Quantity: 3000 Available / 0 Sold\nSeller Information orangstore44 ( 20 ) Ship From: United States Ship To: Worldwide \nMessage us before placing your order NB..Check our telegram well before sending us a message Download any of the fowolling below and add me using and of their username as beneath.. ....Wickr ID......... supplug ....TELEGRAM....... blink9888 ....Whatsapp #.... +1 (252) 368-6780 Amazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift.WU,PAYPA', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 5, 'content': 'Quantity: 3000 Available / 0 Sold\nSeller Information orangstore44 ( 20 ) Ship From: United States Ship To: Worldwide \nMessage us before placing your order NB..Check our telegram well before sending us a message Download any of the fowolling below and add me using and of their username as beneath.. ....Wickr ID......... supplug ....TELEGRAM....... blink9888 ....Whatsapp #.... +1 (252) 368-6780 Amazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift.WU,PAYPA', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 6, 'content': 'Quantity: 3000 Available / 0 Sold\nSeller Information orangstore44 ( 20 ) Ship From: United States Ship To: Worldwide \nMessage us before placing your order NB..Check our telegram well before sending us a message Download any of the fowolling below and add me using and of their username as beneath.. ....Wickr ID......... supplug ....TELEGRAM....... blink9888 ....Whatsapp #.... +1 (252) 368-6780 Amazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift.WU,PAYPA', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 7, 'content': 'Quantity: 3000 Available / 0 Sold\nSeller Information orangstore44 ( 20 ) Ship From: United States Ship To: Worldwide \nMessage us before placing your order NB..Check our telegram well before sending us a message Download any of the fowolling below and add me using and of their username as beneath.. ....Wickr ID......... supplug ....TELEGRAM....... blink9888 ....Whatsapp #.... +1 (252) 368-6780 Amazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift.WU,PAYPA', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 8, 'content': 'Quantity: 3000 Available / 0 Sold\nSeller Information orangstore44 ( 20 ) Ship From: United States Ship To: Worldwide \nMessage us before placing your order NB..Check our telegram well before sending us a message Download any of the fowolling below and add me using and of their username as beneath.. ....Wickr ID......... supplug ....TELEGRAM....... blink9888 ....Whatsapp #.... +1 (252) 368-6780 Amazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift.WU,PAYPA', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 9, 'content': 'Quantity: 9000 Available / 0 Sold\nSeller Information ketyplug ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in seconds.', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 10, 'content': 'Quantity: 19000 Available / 0 Sold\nSeller Information ketyplug ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in seconds', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 11, 'content': 'Quantity: 2300 Available / 0 Sold\nSeller Information marketmans ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in second', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 12, 'content': 'Quantity: 1900 Available / 0 Sold\nSeller Information ketyplug ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in seconds.', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 13, 'content': 'Quantity: 13400 Available / 0 Sold\nSeller Information marketmans ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in secon', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 14, 'content': 'Quantity: 12300 Available / 0 Sold\nSeller Information marketmans ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in secon', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 15, 'content': 'Quantity: 120 Available / 0 Sold\nSeller Information marketmans ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in seconds', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 16, 'content': 'Quantity: 1888 Available / 0 Sold\nSeller Information ketyplug ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in seconds.', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 17, 'content': 'Quantity: 2100 Available / 0 Sold\nSeller Information marketmans ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in second', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 18, 'content': 'Quantity: 120 Available / 0 Sold\nSeller Information marketmans ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in seconds', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 19, 'content': 'Quantity: 120 Available / 0 Sold\nSeller Information marketmans ( 0 ) Ship From: Anonymous Ship To: Worldwide \nAmazon, Google Play gift cards, eBay and Walmart gift cards with codes both physical and E-gift. PRICES ARE $1000 Gift card= $300 test run $2500 Gift card= $600 $4000 Gift card= $1000 We offer fast and secured delivery to all location,Overnight delivery available for USA buyers. Tracking info provided/We are able to make transfers to : USA, UK, CA, AU, EU,AFRICA,ASIA and India in seconds', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'market_yakuza'}, {'aggregate_alert_id': 20, 'content': '@ATT must be hacked right now-I was transferred to the customer loyalty department, a rep. told me their systems have been down for hours & will be “updating” for the next 1-3 hours. When I call the number directly I get a spam call center they said I won a $100 Walmart gift card', 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'twitter'}, {'aggregate_alert_id': 21, 'content': "No.41942350\nFile:  1536431212214651054.gif (https://i.4cdn.org/biz/1634363804039.gif)  (1.89 MB, 400x225) \n1.89 MB GIF \n(https://i.4cdn.org/biz/1634363804039.gif) \nI just noticed I can buy amazon, walmart, zalando gift cards with crypto \nwhat's even the point of cashing out then lol", 'date': '2021-11-02 06:00:26', 'read': False, 'site': 'forum_4chan'}, {'aggregate_alert_id': 22, 'content': '** Description **\nMessage us before placing your order\nNB..Check our telegram well before sending us a message\nTelegram...@ketfox123\nWhatsap...+4915211601214\nwickr..babiju', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'market_darkfox'}, {'aggregate_alert_id': 23, 'content': '** Description **\nMessage us before placing your order\nNB..Check our telegram well before sending us a message\nTelegram...@ketfox123\nWhatsap...+4915211601214\nwickr..babiju', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'market_darkfox'}, {'aggregate_alert_id': 24, 'content': 'Доброго времени суток, интересует наличие у местных продавцов аккаунтов Walmart с привязанными Gift Card номиналом 25-100$, готов покупать на постоянной основе, не единоразово. Пишите в ЛС свой %.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_venera'}, {'aggregate_alert_id': 25, 'content': 'No.344528231\nFile:  Burkholderia pseudomallei.png (https://i.4cdn.org/pol/1635005088294.png)  (202 KB, 1080x850) \n202 KB PNG \n(https://i.4cdn.org/pol/1635005088294.png) \nhttps://www.cpsc.gov/Recalls/2022/W almart-Recalls-Better-Homes-and-Gar dens-Essential-Oil-Infused-Aromathe rapy-Room-Spray-with-Gemstones-Due- to-Rare-and-Dangerous-Bacteria-Two- Deaths-Investigated \nTests conducted by the Centers for Disease Control and Prevention (CDC) determined that a bottle of the room spray contained the ', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_4chan'}, {'aggregate_alert_id': 26, 'content': 'Free CC Sample,I Sell Cvv,Bank transfer,Atm Skimmer,tRACK\n1&2,Banklogins,Atm plastic!!!\n-------------- My Business Regulations ---------------------------\n- I can do make wu transfer very good and speed.\n- I promise cc of me very good and fresh all with good price .\n- If cc not good then i don`t sell', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 27, 'content': 'Free CC Sample,I Sell Cvv,Bank transfer,Atm Skimmer,tRACK\n1&2,Banklogins,Atm plastic!!!\n-------------- My Business Regulations ---------------------------\n- I can do make wu transfer very good and speed.\n- I promise cc of me very good and fresh all with good price .\n- If cc not good then i don`t sell', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 28, 'content': 'Free CC Sample,I Sell Cvv,Bank transfer,Atm Skimmer,tRACK\n1&2,Banklogins,Atm plastic!!!\n-------------- My Business Regulations ---------------------------\n- I can do make wu transfer very good and speed.\n- I promise cc of me very good and fresh all with good price .\n- If cc not good then i don`t sell', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 29, 'content': 'Free CC Sample,I Sell Cvv,Bank transfer,Atm Skimmer,tRACK\n1&2,Banklogins,Atm plastic!!!\n-------------- My Business Regulations ---------------------------\n- I can do make wu transfer very good and speed.\n- I promise cc of me very good and fresh all with good price .\n- If cc not good then i don`t sell', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 30, 'content': 'Free CC Sample,I Sell Cvv,Bank transfer,Atm Skimmer,tRACK\n1&2,Banklogins,Atm plastic!!!\n-------------- My Business Regulations ---------------------------\n- I can do make wu transfer very good and speed.\n- I promise cc of me very good and fresh all with good price .\n- If cc not good then i don`t sell', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 31, 'content': 'Free CC Sample,I Sell Cvv,Bank transfer,Atm Skimmer,tRACK\n1&2,Banklogins,Atm plastic!!!\n-------------- My Business Regulations ---------------------------\n- I can do make wu transfer very good and speed.\n- I promise cc of me very good and fresh all with good price .\n- If cc not good then i don`t sell', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 32, 'content': 'Free CC Sample,I Sell Cvv,Bank transfer,Atm Skimmer,tRACK\n1&2,Banklogins,Atm plastic!!!\n-------------- My Business Regulations ---------------------------\n- I can do make wu transfer very good and speed.\n- I promise cc of me very good and fresh all with good price .\n- If cc not good then i don`t sell', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 33, 'content': 'Free CC Sample,I Sell Cvv,Bank transfer,Atm Skimmer,tRACK\n1&2,Banklogins,Atm plastic!!!\n-------------- My Business Regulations ---------------------------\n- I can do make wu transfer very good and speed.\n- I promise cc of me very good and fresh all with good price .\n- If cc not good then i don`t sell', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 34, 'content': 'Free CC Sample,I Sell Cvv,Bank transfer,Atm Skimmer,tRACK\n1&2,Banklogins,Atm plastic!!!\n-------------- My Business Regulations ---------------------------\n- I can do make wu transfer very good and speed.\n- I promise cc of me very good and fresh all with good price .\n- If cc not good then i don`t sell', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 35, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 36, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 37, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 38, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 39, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 40, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 41, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 42, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 43, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 44, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 45, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 46, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 47, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 48, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}, {'aggregate_alert_id': 49, 'content': 'I Am Offering Legits Hack Service and Hacking Tools, CCV, CC,PayPal,\nWU, MG,Fullz.....\nEthical Hacking like any other forensic science involves the use of\nsophisticated technology tools and procedures that must be followed to\nguarantee the accuracy of the preservation/documentation of evidence,\nidentification, extraction and the accuracy of results.', 'date': '2021-11-02 06:00:27', 'read': False, 'site': 'forum_cardingmafia'}], 'threat_level': 'imminent', 'threats': ['Fraud'], 'title': 'Gift Cards of Sixgill are Sold on the Underground ', 'user_id': '5d233575f8db38787dbe24b6'}, {'alert_name': "Access to {matched_domain_names}, One of {organization_name}'s Assets, was Compromised and Offered for Sale on a Compromised Endpoint Market", 'category': 'regular', 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PL  |  17  |  2  |  2021-10-19 19:57:25  |  2021-10-27 09:39:16  |  79.163...  |  Windows 10 Home  |  1.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-27 09:39:16             \n 384E75E0851A820644B79EC124865B75 ', 'date': '2021-11-02 06:00:16', 'id': '6180d3f01dbb8edcb496ec86', 'lang': 'English', 'langcode': 'en', 'read': False, 'severity': 1, 'sub_alerts': [{'aggregate_alert_id': 0, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PL  |  17  |  2  |  2021-10-19 19:57:25  |  2021-10-27 09:39:16  |  79.163...  |  Windows 10 Home  |  1.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-27 09:39:16             \n 384E75E0851A820644B79EC124865B75 ', 'date': '2021-11-02 06:00:15', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 1, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n NP  |  6  |  2  |  2021-10-26 05:56:54  |  2021-10-30 18:18:41  |  103.41...  |  Windows 10 Home  |  13.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-28 17:07:42             \n 096EE94620756A0D333FD6767728AD60 ', 'date': '2021-11-02 06:00:15', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 2, 'content': 'Stealer:\nAZORult\nCountry:\nFree and Hanseatic City of Hamburg  ISP: Vodafone Kabel Deutschland\nLinks:\nsh-netz.com', 'date': '2021-11-02 06:00:15', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 3, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PL  |  9  |  1  |  2021-10-31 21:23:38  |  2021-11-01 08:57:43  |  188.147...  |  Windows 10 Home  |  6.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-11-01 08:57:43             \n BB2DC9817F2AB9B37AFF0DADA9095BBA ', 'date': '2021-11-02 06:00:15', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 4, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n GR  |  12  |  2  |  2021-10-20 12:41:58  |  2021-10-20 17:41:56  |  85.75...  |  Windows 10 Pro  |  26.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-20 13:10:09             \n DB5545D9158907A8A328F6AA25FDCD05 ', 'date': '2021-11-02 06:00:15', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 5, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n IT  |  59  |  4  |  2021-10-30 13:58:30  |  2021-10-31 18:27:36  |  151.26...  |  Windows 10 Home  |  12.00   \nBots group info:\nBOT NAME  |  INSTALLED  |  UPDATED  |  BOT RESOURCES  |  COUNTRY  |  HOST  |  OS\n2EC2F88C9C44EB276301EAB51FBC42CD  |  2021-10-30 13:58:30  |   2021-10-31 18:27:36  |  PayPal, Amazon, MEGAnz, ZalandoStore, Google, Ebay, com.instagram.android, com.madfut.ma', 'date': '2021-11-02 06:00:15', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 6, 'content': 'Stealer:\nRedline\nCountry:\nOdessa  ISP: Aries Ltd.\nLinks:\npiratbit.gq', 'date': '2021-11-02 06:00:15', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 7, 'content': 'Stealer:\nRedline\nCountry:\nOdessa  ISP: Aries Ltd.\nLinks:\npiratbit.gq', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 8, 'content': 'Stealer:\nRedline\nCountry:\nOdessa  ISP: Aries Ltd.\nLinks:\npiratbit.gq', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 9, 'content': 'Stealer:\nRedline\nCountry:\nOdessa  ISP: Aries Ltd.\nLinks:\npiratbit.gq', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 10, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n US  |  10  |  3  |  2021-10-07 20:33:48  |  2021-10-27 20:29:23  |  96.230...  |  None  |  5.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-27 20:29:23             \n C2C288A6A914E06CCAE1F47118661919 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 11, 'content': 'Country: WW\nSeller Rating: 62%\nTags:  28.10.2021 worked out crypto, youtube, facebook, networks\nhttps://t.me/REDLINESUPPORT\nhttps://unite.nike.com/\nhttps://telefonicacolombiaprod.b2clogin.com/', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_2easy'}, {'aggregate_alert_id': 12, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n HR  |  24  |  2  |  2021-10-28 23:11:23  |  2021-10-29 08:57:02  |  188.252...  |  Windows 10 Pro  |  8.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-29 08:57:02             \n CA62900B0455F31C19ED8662E90EDD8E ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 13, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PL  |  20  |  2  |  2021-10-27 15:25:10  |  2021-10-27 20:29:24  |  46.204...  |  Windows 10 Home  |  8.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-27 20:29:24             \n 08554CD541922F39C8EDA208C9C7052D ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 14, 'content': 'Stealer:\nRedline\nCountry:\nOdessa  ISP: PP "Zastava Plus"\nLinks:\nmir-kolgot.com.ua', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 15, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PT  |  44  |  2  |  2021-10-31 14:55:41  |  2021-10-31 17:49:13  |  85.242...  |  Windows 10 Home  |  11.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-31 16:03:26             \n DA1DB0805AC2E55848FAFC50442682C9 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 16, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n SE  |  20  |  2  |  2021-10-31 22:35:13  |  2021-11-01 06:03:49  |  85.238...  |  Windows 10 Home  |  6.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-11-01 06:03:49             \n AA029C309AFDA6370090ECFEBECDB156 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 17, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n CL  |  37  |  3  |  2021-10-27 03:20:16  |  2021-10-28 06:23:05  |  190.47...  |  Windows 10 Home  |  11.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-28 06:23:05             \n 19E889656CFBAD7B8D6BA6016041B272 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 18, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n ES  |  36  |  2  |  2021-10-20 18:55:02  |  2021-10-21 14:28:45  |  90.94...  |  Windows 10 Home  |  7.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-21 14:28:45             \n DDC3B48B9A616FA3EF27F55303A439CF ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 19, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n ES  |  25  |  2  |  2021-09-03 09:28:04  |  2021-10-28 06:23:04  |  188.26...  |  None  |  6.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-28 06:23:04             \n BA60EA66D35F2BF080ECEF389FAAD05E ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 20, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n NL  |  27  |  2  |  2021-10-27 15:16:53  |  2021-10-27 18:36:55  |  62.45...  |  Windows 10 Home  |  9.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-27 15:51:40             \n 097A151800477FBF5626E49D0FC42DCD ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 21, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n RO  |  23  |  2  |  2021-10-27 21:37:54  |  2021-10-29 08:57:02  |  81.196...  |  Windows 10 Home  |  17.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-29 08:57:02             \n BEC668200673739304C5C3FA124AC18B ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 22, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PL  |  37  |  3  |  2021-10-29 06:29:29  |  2021-10-30 11:38:23  |  46.45...  |  Windows 7 Professional  |  25.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-30 11:38:23             \n E32A2F7B966D512BD9E54B77D18C37E2 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 23, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PL  |  154  |  4  |  2021-09-08 10:32:23  |  2021-10-31 18:29:30  |  91.189...  |  Windows 10 Pro  |  25.00   \nBots group info:\nBOT NAME  |  INSTALLED  |  UPDATED  |  BOT RESOURCES  |  COUNTRY  |  HOST  |  OS\nCF6F6A58FFD90B4AF91457891BE5EF76  |  2021-09-08 10:32:23  |   2021-10-31 18:29:30  |  ZalandoStore, MEGAnz, Spotify, Facebook, Amazon, O2, Netflix, Google, PayPal, gra.mobi, ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 24, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n IT  |  77  |  3  |  2021-10-28 20:06:37  |  2021-10-29 08:57:02  |  91.187...  |  Windows 10 Enterprise  |  25.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-29 08:57:02             \n 50B230460EF4E2349EA45C362F5830DE ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 25, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n ES  |  30  |  4  |  2021-10-28 11:22:37  |  2021-10-31 12:56:07  |  62.174...  |  Windows 10 Pro  |  8.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-31 12:56:07             \n 43FEDE3B944E1A61D757044DD3A05A81 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 26, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n IT  |  25  |  3  |  2021-09-08 16:36:31  |  2021-10-21 14:28:45  |  93.144...  |  Windows 10 Home  |  9.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-21 14:28:45             \n AF0870D328F1930BA617404BA50EA2F8 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 27, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PT  |  42  |  2  |  2021-10-24 02:22:32  |  2021-10-25 07:51:31  |  81.20...  |  Windows 10 Pro  |  10.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-25 07:51:31             \n 92468AD9D54A424D52E467FF1F90EE16 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 28, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n US  |  37  |  1  |  2021-11-01 00:25:23  |  2021-11-01 06:03:49  |  208.104...  |  Windows 10 Home  |  25.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-11-01 06:03:49             \n 4DFCB129C68C05BA550471159D160CCB ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 29, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n RO  |  52  |  3  |  2021-10-28 21:58:04  |  2021-10-29 08:57:02  |  84.232...  |  Windows 10 Pro  |  7.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-29 08:57:02             \n 0E8C98C089CCEB124D6C176092C983B6 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 30, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PL  |  36  |  3  |  2021-10-28 16:51:23  |  2021-10-28 19:08:12  |  185.172...  |  Windows 10 Home  |  19.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-28 17:07:43             \n A25B0646A7B4651DC87BCCDE2796AE9E ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 31, 'content': 'Stealer:\nRedline\nCountry:\nNisava  ISP: Jotel d.o.o.\nLinks:\nservisi.euprava.gov.rs', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 32, 'content': 'Stealer:\nRedline\nCountry:\nNisava  ISP: Jotel d.o.o.\nLinks:\nservisi.euprava.gov.rs', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 33, 'content': 'Stealer:\nRedline\nCountry:\nSouth Korea  Gyeonggi-do  ISP: Korea Telecom\nLinks:\nmy.minecraft.net', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 34, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PT  |  92  |  1  |  2021-10-26 14:45:48  |  2021-10-26 20:06:54  |  144.64...  |  Windows 10 Pro  |  19.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-26 18:14:13             \n 03879A60BBFB90D41E60C6E6AF18CA97 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 35, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n FR  |  35  |  4  |  2021-09-10 20:38:14  |  2021-10-25 07:51:28  |  90.40...  |  Windows 10 Famille  |  10.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-25 07:51:28             \n 50E88362B737869DD2C0A00082D2CC43 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 36, 'content': 'Stealer:\nRedline\nCountry:\nTlaxcala  ISP: Uninet S.A. de C.V.\nLinks:\nguiaexarmed.com.mx', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 37, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n GR  |  49  |  2  |  2021-10-10 13:39:02  |  2021-10-28 19:23:35  |  109.242...  |  Windows 10 Home Single Language  |  14.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-28 17:07:41             \n 649FC8CAA998D20E1B6B2766A67D3D0D ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 38, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n RO  |  90  |  2  |  2021-10-23 21:59:02  |  2021-10-24 06:03:51  |  109.98...  |  Windows 10 Pro  |  11.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-23 23:45:47             \n DB71F3D4A1F82164E2D7C944C1F0D775 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 39, 'content': 'Stealer:\nRedline\nCountry:\nIstanbul  ISP: Turkcell Internet\nLinks:\nangora.baskent.edu.tr', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 40, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n CA  |  124  |  2  |  2021-10-20 00:24:01  |  2021-10-20 06:30:44  |  142.184...  |  Windows 10 Alienware Windows 10 Alienware Edition 2019  |  113.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-20 06:30:44             \n 45675E013F4644DC58428B6A445D4100 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 41, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n SE  |  56  |  3  |  2021-10-30 12:51:17  |  2021-10-30 17:57:00  |  82.96...  |  Windows 10 Home  |  17.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-30 13:25:21             \n 0D8A1656B51C3074BA3D14D306B790D2 ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 42, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PT  |  43  |  1  |  2021-09-30 18:41:08  |  2021-10-30 06:41:29  |  188.37...  |  Windows 7 Ultimate  |  20.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-01 07:13:08             \n 8BA48A6BFD476612D740E01A9F910F6E ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 43, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n ES  |  105  |  4  |  2021-09-14 11:49:37  |  2021-10-31 18:27:52  |  81.40...  |  Windows 10 Home  |  15.00   \nBots group info:\nBOT NAME  |  INSTALLED  |  UPDATED  |  BOT RESOURCES  |  COUNTRY  |  HOST  |  OS\n0F304C525E3E2D32A166E7296FF067E1  |  2021-09-14 11:49:37  |   2021-10-31 18:27:52  |  Dropbox, Google, Habbo, Elcorteingles..., Adobe, Live, Spotify, Netflix, Twitter, PayPal', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 44, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PL  |  124  |  4  |  2021-10-30 13:29:35  |  2021-10-31 18:28:00  |  37.131...  |  Windows 10 Home  |  20.00   \nBots group info:\nBOT NAME  |  INSTALLED  |  UPDATED  |  BOT RESOURCES  |  COUNTRY  |  HOST  |  OS\n443285B2E5951F7C9204A7358ACB6F92  |  2021-10-30 13:29:35  |   2021-10-31 18:28:00  |  Live, Amazon, Facebook, Google, Instagram, Steam, PayPal, tv.twitch.android.app, accoun', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 45, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n GR  |  126  |  4  |  2021-10-26 05:04:12  |  2021-10-26 06:16:24  |  94.67...  |  Windows 10 Home  |  22.00   \nBrowsers for Genesis Security: \n Last update info: : 2021-10-26 06:16:24             \n 3AF1A175CB0879F9412108EA6BBC93AF ', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis'}, {'aggregate_alert_id': 46, 'content': 'Bots head info:\n COUNTRY   |  RESOURCES   |  BROWSERS   |   INSTALLED   |   UPDATED   |  IP  |  OS  |  PRICE USD   \n PT  |  151  |  3  |  2021-09-02 22:39:09  |  2021-10-31 18:28:54  |  2.82...  |  Windows 10 Home  |  28.00   \nBots group info:\nBOT NAME  |  INSTALLED  |  UPDATED  |  BOT RESOURCES  |  COUNTRY  |  HOST  |  OS\nE89C60E2F3860CC10250BFBE193C2804  |  2021-09-02 22:39:09  |   2021-10-31 18:28:54  |  Amazon, Steam, Google, Aliexpress, Alibaba, Paysafecard, Reddit, Twitter, Spotify, League', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_genesis', 'status': {'name': 'in_treatment', 'user': '5d5cdbad19468b088fadbfff'}}, {'aggregate_alert_id': 47, 'content': 'Stealer:\nRedline\nCountry:\nKelantan  ISP: TMnet\nLinks:\nepicgames.com', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 48, 'content': 'Stealer:\nRedline\nCountry:\nKelantan  ISP: TMnet\nLinks:\nepicgames.com', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}, {'aggregate_alert_id': 49, 'content': 'Stealer:\nRedline\nCountry:\nKelantan  ISP: TMnet\nLinks:\nepicgames.com', 'date': '2021-11-02 06:00:16', 'read': False, 'site': 'market_russianmarket'}], 'threat_level': 'imminent', 'threats': ['Compromised Accounts'], 'title': "Access to your organization's Assets was Compromised and Offered for Sale on a Compromised Endpoint Market", 'user_id': '5d233575f8db38787dbe24b6'}]

info_item = {
  "additional_info": {
    "asset_attributes": [
      "organization_aliases",
      "domain_names"
    ],
    "domain_names": [
      "bank.com",
      "nike.com",
      "cybersixgill.com",
      "meineschufa.de",
      "bank.com",
      "test.com",
      "eitan.com"
    ],
    "matched_domain_names": [],
    "matched_organization_aliases": [
      "Walmart"
    ],
    "organization_aliases": [
      "walmart",
      "cybersixgill",
      "nike"
    ],
    "organization_name": "Cybersixgill",
    "post_attributes": [
      "site"
    ],
    "query_attributes": [
      "organization_aliases",
      "domain_names"
    ],
    "site": "rw_everest",
    "template_id": "5fd0d2acddd06410ac5348d1",
    "vendor": "Sixgill"
  },
  "alert_id": "616ffed97a1b66036a138f73",
  "alert_name": "Your organization was potentially targeted by a ransomware group",
  "alert_type": "QueryBasedManagedAlertRule",
  "assessment": "This could indicate that \"Walmart\" is being actively attacked by a ransomware campaign, or that its data has already been compromised and dumped publicly on the site.",
  "category": "regular",
  "content_type": "search_result_item",
  "description": "A ransomware group posted on its leak site, rw_everest, focusing on \"Walmart\" ",
  "es_id": "51baa80bb1a01ba4b4a08f59a2313ff60e78bf75",
  "es_item": {},
  "id": "6188bd21017198385e228437",
  "lang": "English",
  "langcode": "en",
  "read": True,
  "recommendations": [],
  "severity": 1,
  "site": "rw_everest",
  "status": {
    "name": "in_treatment",
    "user": "60b604a048ce2cb294629a2d"
  },
  "summary": "",
  "threat_level": "imminent",
  "threats": [
    "Brand Protection",
    "Data Leak"
  ],
  "title": "Your organization was potentially targeted by a ransomware group",
  "update_time": "2021-11-08 06:01:05",
  "user_id": "5d233575f8db38787dbe24b6"
}

content_item = {
  "content": {
    "items": [
      {
        "_id": "51baa80bb1a01ba4b4a08f59a2313ff60e78bf75",
        "_source": {
          "_op_type": "update",
          "category": "Ransomware",
          "collection_date": "2021-05-11T13:11:46",
          "comments_count": 0,
          "content": "Full documentation includes architecture, electricity, structure, security and more .\n\nPoirier Sport Complex (PSLC) Arena 3 Conversion – Phase 2, Coquitlam BC  \nCapilano University Library Reno / Center for Student Success – Phase 2  \nWalmart 3042 Kelowna Relay\n\nCity of Vancouver 2780 East Broadway\n\nCompany:Traugott Building Contractors Inc.\n Address:3740 11A Street NE, Unit 101B \nCalgary, Alberta T2E 6M6 Canada\n Website: http://traugott.com \n Email:bids@traugott.com\n Phone:(403) 276-6444\n Files: Traugott_Building_Contractors_Inc.zip (http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/Traugott_Building_Contractors_Inc.zip) \n Published data: 2 GB\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n",
          "creator": "Everest ransom team",
          "date": "2021-05-11T13:11:46",
          "enrichment_version": 46,
          "financial": {
            "iban": [],
            "swift": []
          },
          "id": "44",
          "images": [
            {
              "key": "rw_everest/e3d3404a4e8b0d9cc984818d815e1275.jpg",
              "pos": 674
            },
            {
              "key": "rw_everest/3f71c5c463ae9f5918bfda0d1ee5b1aa.jpg",
              "pos": 676
            },
            {
              "key": "rw_everest/2e7593a297683d8e8f776afa13c1d92b.jpg",
              "pos": 678
            },
            {
              "key": "rw_everest/4bda3ab9f2a73cd037edbb2ca62458d0.jpg",
              "pos": 680
            },
            {
              "key": "rw_everest/16bf9c99a75ea7c3ffbb21a11ee1ca03.jpg",
              "pos": 682
            },
            {
              "key": "rw_everest/a75763eef71f52f4b05132a9843e2eb3.jpg",
              "pos": 684
            },
            {
              "key": "rw_everest/678fd81d6ca5ced070f0cc9ce4b47a86.jpg",
              "pos": 686
            },
            {
              "key": "rw_everest/ebe9c72aeed3cdfbd7bb68bd3a262b90.jpg",
              "pos": 688
            }
          ],
          "ips": [],
          "lang": "en",
          "length": {
            "content": 688,
            "title": 34
          },
          "location": [
            "Calgary",
            "Canada",
            "Coquitlam",
            "Kelowna"
          ],
          "modules": [
            "ddw"
          ],
          "organization": [
            "Traugott Building Contractors Inc."
          ],
          "pds": {
            "email_address": [
              "bids@traugott.com"
            ],
            "phone_number": [
              "4032766444"
            ]
          },
          "product": [
            "Alberta T2E 6M6 Canada"
          ],
          "rep_grade": 1,
          "site": "rw_everest",
          "site_grade": 5,
          "source_type": "rw",
          "sub_category": "",
          "tags": [
            "Ransomware",
            "Phone_number",
            "email",
            "Email_address"
          ],
          "title": "Traugott Building Contractors Inc.",
          "type": "post",
          "update_date": "2021-11-07T15:58:04.131371"
        },
        "triggered_alert": True
      },
      {
        "_id": "51baa80bb1a01ba4b4a08f59a2313ff60e78bf75",
        "_source": {
          "category": "Ransomware",
          "collection_date": "2021-11-07T14:55:26",
          "comments_count": 0,
          "content": "Full documentation includes architecture, electricity, structure, security and more .\n\nPoirier Sport Complex (PSLC) Arena 3 Conversion – Phase 2, Coquitlam BC  \nCapilano University Library Reno / Center for Student Success – Phase 2  \nWalmart 3042 Kelowna Relay\n\nCity of Vancouver 2780 East Broadway\n\nCompany:Traugott Building Contractors Inc.\n Address:3740 11A Street NE, Unit 101B \nCalgary, Alberta T2E 6M6 Canada\n Website: http://traugott.com [http://www.traugott.com/]  \n Email:bids@traugott.com\n Phone:(403) 276-6444\n Files: Traugott_Building_Contractors_Inc.zip (http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/Traugott_Building_Contractors_Inc.zip) \n Published data: 2 GB\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n",
          "creator": "Everest ransom team",
          "date": "2021-11-07T14:55:26",
          "enrichment_version": 46,
          "financial": {
            "iban": [],
            "swift": []
          },
          "id": "44",
          "images": [
            {
              "is_emoji": False,
              "key": "rw_everest/e3d3404a4e8b0d9cc984818d815e1275.jpg",
              "metadata": None,
              "ocr_text_info": {
                "all_text": "ROUMDATION ND ROUND FLODRPLAN MOTES\n",
                "is_arabic": False
              },
              "pos": 674,
              "safe_search": {
                "adult": 1,
                "medical": 1,
                "spoof": 1,
                "violence": 1
              },
              "size": {
                "height": 605,
                "width": 1024
              },
              "text": "ROUMDATION ND ROUND FLODRPLAN MOTES\n"
            },
            {
              "is_emoji": False,
              "key": "rw_everest/3f71c5c463ae9f5918bfda0d1ee5b1aa.jpg",
              "metadata": None,
              "ocr_text_info": {
                "all_text": "器\nWaimart*\n",
                "is_arabic": False
              },
              "pos": 676,
              "safe_search": {
                "adult": 1,
                "medical": 1,
                "spoof": 1,
                "violence": 1
              },
              "size": {
                "height": 424,
                "width": 1024
              },
              "text": "器\nWaimart*\n"
            },
            {
              "is_emoji": False,
              "key": "rw_everest/2e7593a297683d8e8f776afa13c1d92b.jpg",
              "metadata": None,
              "ocr_text_info": {
                "all_text": "O A1.4 FLOOR FINISH PLAN-3042 A1\nFirefox HTML Document\nO D1.0 DEMO PLAN-3042 D1\nFirefox HTML Document\nO E1.0 Lighting Plan\nFirefox HTML Document\nO E1.1 Lighting Details\nFirefox HTML Document\nO E1.5 Lighting Details\nFirefox HTML Document\nE E2.0 Power and Low Tension\nFirefox HTML Document\nO E2.2 Power and Low Tension Details\nFirefox HTML Document\nE2.5 Power and Low Tension Details\nFirefox HTML Document\nO E5.0b Construction Power Drop Plan\nFirefox HTML Document\nE6.0 Schedules and single line diag. Firefox HTML Document\nO EC2.0 ECOMM PLANS-3042 EC2\nFirefox HTML Document\nGP2.0-Exist GroceryDemo-Water-G... Firefox HTML Document\nGP2.1_Exist GroceryDemo-Water-G.. Firefox HTML Document\nO MED1\nFirefox HTML Document\nMED3.0 MEDICAL DOCTORS OFFIC. Firefox HTML Document\nMP1.1 HVAC_Plumb Roof Plan-MP... Firefox HTML Document\nO P2.4_Enlarged Plumbing Plans Ne..\nO P3.0_Plumbing Details-P3.0\nFirefox HTML Document\nFirefox HTML Document\n",
                "is_arabic": False
              },
              "pos": 678,
              "safe_search": {
                "adult": 1,
                "medical": 2,
                "spoof": 2,
                "violence": 2
              },
              "size": {
                "height": 758,
                "width": 774
              },
              "text": "O A1.4 FLOOR FINISH PLAN-3042 A1\nFirefox HTML Document\nO D1.0 DEMO PLAN-3042 D1\nFirefox HTML Document\nO E1.0 Lighting Plan\nFirefox HTML Document\nO E1.1 Lighting Details\nFirefox HTML Document\nO E1.5 Lighting Details\nFirefox HTML Document\nE E2.0 Power and Low Tension\nFirefox HTML Document\nO E2.2 Power and Low Tension Details\nFirefox HTML Document\nE2.5 Power and Low Tension Details\nFirefox HTML Document\nO E5.0b Construction Power Drop Plan\nFirefox HTML Document\nE6.0 Schedules and single line diag. Firefox HTML Document\nO EC2.0 ECOMM PLANS-3042 EC2\nFirefox HTML Document\nGP2.0-Exist GroceryDemo-Water-G... Firefox HTML Document\nGP2.1_Exist GroceryDemo-Water-G.. Firefox HTML Document\nO MED1\nFirefox HTML Document\nMED3.0 MEDICAL DOCTORS OFFIC. Firefox HTML Document\nMP1.1 HVAC_Plumb Roof Plan-MP... Firefox HTML Document\nO P2.4_Enlarged Plumbing Plans Ne..\nO P3.0_Plumbing Details-P3.0\nFirefox HTML Document\nFirefox HTML Document\n"
            },
            {
              "is_emoji": False,
              "key": "rw_everest/4bda3ab9f2a73cd037edbb2ca62458d0.jpg",
              "metadata": None,
              "ocr_text_info": {
                "all_text": "O 00100, 00300, 00301, 00302, 00303, ..\nO 00110 - Pre-Qualified Roofing and\n00811 - Supplementary Conditions . Firefox HTML Document\nFirefox HTML Document\nFirefox HTML Document\nE 01010 - Summary of Work\nFirefox HTML Document\n01036 - Request for Information (RFI) Firefox HTML Document\nO 01037 - Owner Construction Reports\nFirefox HTML Document\n01041 - Project Co-Ordination\nFirefox HTML Document\n01045 - Cutting and Patching\n01050 - Field Engineering\nFirefox HTML Document\nFirefox HTML Document\n01060 - Regulatory Requirements - . Firefox HTML Document\n01110 Alteration Project Procedur..\nFirefox HTML Document\nS 01200 - Project Meetings\nFirefox HTML Document\n- 01300 - Submittals\nFirefox HTML Document\n01310 Progress Schedules\nFirefox HTML Document\n01351 Community Liaison\nFirefox HTML Document\nO 01452 - Contractors Quality Control\nFirefox HTML Document\n01454 - Consultant Quality Assuran..\nFirefox HTML Document\nO 01455 - Mechanical Equipment, Te..\nFirefox HTML Document\n",
                "is_arabic": False
              },
              "pos": 680,
              "safe_search": {
                "adult": 1,
                "medical": 2,
                "spoof": 1,
                "violence": 2
              },
              "size": {
                "height": 752,
                "width": 826
              },
              "text": "O 00100, 00300, 00301, 00302, 00303, ..\nO 00110 - Pre-Qualified Roofing and\n00811 - Supplementary Conditions . Firefox HTML Document\nFirefox HTML Document\nFirefox HTML Document\nE 01010 - Summary of Work\nFirefox HTML Document\n01036 - Request for Information (RFI) Firefox HTML Document\nO 01037 - Owner Construction Reports\nFirefox HTML Document\n01041 - Project Co-Ordination\nFirefox HTML Document\n01045 - Cutting and Patching\n01050 - Field Engineering\nFirefox HTML Document\nFirefox HTML Document\n01060 - Regulatory Requirements - . Firefox HTML Document\n01110 Alteration Project Procedur..\nFirefox HTML Document\nS 01200 - Project Meetings\nFirefox HTML Document\n- 01300 - Submittals\nFirefox HTML Document\n01310 Progress Schedules\nFirefox HTML Document\n01351 Community Liaison\nFirefox HTML Document\nO 01452 - Contractors Quality Control\nFirefox HTML Document\n01454 - Consultant Quality Assuran..\nFirefox HTML Document\nO 01455 - Mechanical Equipment, Te..\nFirefox HTML Document\n"
            },
            {
              "is_emoji": False,
              "key": "rw_everest/16bf9c99a75ea7c3ffbb21a11ee1ca03.jpg",
              "metadata": None,
              "ocr_text_info": {
                "all_text": "s and Views\n-000\n-001\n-002\n-003\n-101\n-111\n101\n111\n121\nGENERAL NOTES\n",
                "is_arabic": False
              },
              "pos": 682,
              "safe_search": {
                "adult": 1,
                "medical": 1,
                "spoof": 1,
                "violence": 1
              },
              "size": {
                "height": 484,
                "width": 1024
              },
              "text": "s and Views\n-000\n-001\n-002\n-003\n-101\n-111\n101\n111\n121\nGENERAL NOTES\n"
            },
            {
              "is_emoji": False,
              "key": "rw_everest/a75763eef71f52f4b05132a9843e2eb3.jpg",
              "metadata": None,
              "ocr_text_info": {
                "all_text": "Hi lain,\nPlease find attached tender specifications. Drawings are on their way.\nCheers,\nKenny\nCAPILANO\nUNIVERSITY\nKenny Fung, P. Eng., PMP, LEED Green Associate\nManager, Project Management | Facilities\n604-785-4326 | kennyfung@capilanou.ca\nNorth Vancouver Campus | 2055 Purcell Way, North Vancouver\nBritish Columbia, Canada V7J 3H5 | capilanou.ca\nCapilano University is named after Chief Joe Capilano, an important leader of the Squamish (Skwxwú7mesh) Nation of the\nCoast Salish people. We respectfully acknowledge that our campuses are located on the territories of the Lil'wat, Musqueam,\nSechelt (shishálh), Squamish and Tsleil-Waututh Nations.\nFrom: Emerson, Matthew <Matthew.Emerson@hdrinc.com>\n",
                "is_arabic": False
              },
              "pos": 684,
              "safe_search": {
                "adult": 1,
                "medical": 2,
                "spoof": 2,
                "violence": 2
              },
              "size": {
                "height": 538,
                "width": 1024
              },
              "text": "Hi lain,\nPlease find attached tender specifications. Drawings are on their way.\nCheers,\nKenny\nCAPILANO\nUNIVERSITY\nKenny Fung, P. Eng., PMP, LEED Green Associate\nManager, Project Management | Facilities\n604-785-4326 | kennyfung@capilanou.ca\nNorth Vancouver Campus | 2055 Purcell Way, North Vancouver\nBritish Columbia, Canada V7J 3H5 | capilanou.ca\nCapilano University is named after Chief Joe Capilano, an important leader of the Squamish (Skwxwú7mesh) Nation of the\nCoast Salish people. We respectfully acknowledge that our campuses are located on the territories of the Lil'wat, Musqueam,\nSechelt (shishálh), Squamish and Tsleil-Waututh Nations.\nFrom: Emerson, Matthew <Matthew.Emerson@hdrinc.com>\n"
            },
            {
              "is_emoji": False,
              "key": "rw_everest/678fd81d6ca5ced070f0cc9ce4b47a86.jpg",
              "metadata": None,
              "ocr_text_info": {
                "all_text": "2 sur 733\n+ Zoom automatique\nCity of Coquitlam\nRFP No. 19-10-06 - Construction Services at PSLC: Arena 3 Conversion - Phase 2\nTABLE OF CONTENTS\nPage\nSUMMARY OF KEY INFORMATION\n.3\nDEFINITIONS.\n1. INSTRUCTIONS TO PROPONENTS\n1.1. Project Description\n1.2. Completion Date..\n1.3. Non-mandatory Site Visit.\n1.4. Instructions to Proponents...\n1.5. Prices....\n1.6. Eligibility.\n1.7. Evaluation Criteria.\n1.8. Negotiation\n1.9. Litigation.\n8\n10\n10\n2. GENERAL CONDITIONs\n11\n",
                "is_arabic": False
              },
              "pos": 686,
              "safe_search": {
                "adult": 1,
                "medical": 1,
                "spoof": 1,
                "violence": 1
              },
              "size": {
                "height": 525,
                "width": 1024
              },
              "text": "2 sur 733\n+ Zoom automatique\nCity of Coquitlam\nRFP No. 19-10-06 - Construction Services at PSLC: Arena 3 Conversion - Phase 2\nTABLE OF CONTENTS\nPage\nSUMMARY OF KEY INFORMATION\n.3\nDEFINITIONS.\n1. INSTRUCTIONS TO PROPONENTS\n1.1. Project Description\n1.2. Completion Date..\n1.3. Non-mandatory Site Visit.\n1.4. Instructions to Proponents...\n1.5. Prices....\n1.6. Eligibility.\n1.7. Evaluation Criteria.\n1.8. Negotiation\n1.9. Litigation.\n8\n10\n10\n2. GENERAL CONDITIONs\n11\n"
            },
            {
              "is_emoji": False,
              "key": "rw_everest/ebe9c72aeed3cdfbd7bb68bd3a262b90.jpg",
              "metadata": None,
              "ocr_text_info": {
                "all_text": "ΝΟΤE.\nTHE POIRIER SPORT AND LEISURE COMPLEX\nIS AN ACTIVE FACILITY. CONSTRUCTION\nSHALL REMAIN OUT SIDE OF THE EXISTING\nBUILDING ENVELOPE FOR THE MAJORITY OF\nTHE CONSTRUCTION DURATION. IT IS\nANTICIPATED THAT A+-2 WEEK SHUT\na Cga\nDOWN WILL BE REQUIRED OF THE\nADJACENT ARENA S FOR INTERNAL WORK\nAND TIE-INS. THIS TIMEFRAME WILL BE\nNEGOTIATED WITH THE SUCCESSFUL\nPROPONENT\nSITE PLAN LEGEND\nLERUAE CONTETONNGAN\nDEMOLITION NOTES\nFOR WORK\nNOTES\nMETRIC\nreer NN N\nRERTO MEC\nFOR WOK\nA ear\nNG LL\nNG avALL CA STLLE\nFORNEWOWLK\nSARGENT CRESCENT\n",
                "is_arabic": False
              },
              "pos": 688,
              "safe_search": {
                "adult": 1,
                "medical": 1,
                "spoof": 1,
                "violence": 1
              },
              "size": {
                "height": 452,
                "width": 1024
              },
              "text": "ΝΟΤE.\nTHE POIRIER SPORT AND LEISURE COMPLEX\nIS AN ACTIVE FACILITY. CONSTRUCTION\nSHALL REMAIN OUT SIDE OF THE EXISTING\nBUILDING ENVELOPE FOR THE MAJORITY OF\nTHE CONSTRUCTION DURATION. IT IS\nANTICIPATED THAT A+-2 WEEK SHUT\na Cga\nDOWN WILL BE REQUIRED OF THE\nADJACENT ARENA S FOR INTERNAL WORK\nAND TIE-INS. THIS TIMEFRAME WILL BE\nNEGOTIATED WITH THE SUCCESSFUL\nPROPONENT\nSITE PLAN LEGEND\nLERUAE CONTETONNGAN\nDEMOLITION NOTES\nFOR WORK\nNOTES\nMETRIC\nreer NN N\nRERTO MEC\nFOR WOK\nA ear\nNG LL\nNG avALL CA STLLE\nFORNEWOWLK\nSARGENT CRESCENT\n"
            }
          ],
          "ips": [],
          "lang": "en",
          "length": {
            "content": 688,
            "title": 34
          },
          "location": [
            "Calgary",
            "Canada",
            "Coquitlam",
            "Kelowna"
          ],
          "modules": [
            "ddw"
          ],
          "pds": {
            "email_address": [
              "bids@traugott.com"
            ],
            "phone_number": [
              "4032766444"
            ]
          },
          "rep_grade": 1,
          "site": "rw_everest",
          "site_grade": 5,
          "source_type": "rw",
          "sub_category": "",
          "tags": [
            "Ransomware",
            "Phone_number",
            "email",
            "Email_address"
          ],
          "title": "Traugott Building Contractors Inc.",
          "type": "post",
          "update_date": "2021-11-07T14:56:48.135426"
        },
        "triggered_alert": True
      }
    ],
    "total": 2
  },
  "content_type": "search_result_item"
}

expected_alert_output = [{'name': 'Your organization was potentially targeted by a ransomware group', 'occurred': '2021-11-08T06:01:05.000000Z', 'severity': 3, 'description': 'A ransomware group posted on its leak site, rw_everest, focusing on "Walmart" ', 'CustomFields': {'cybersixgillthreatlevel': 'imminent', 'cybersixgillportalurl': 'https://portal.cybersixgill.com/#/?actionable_alert=6188bd21017198385e228437', 'cybersixgillthreattype': ['Brand Protection', 'Data Leak'], 'cybersixgillassessment': 'This could indicate that "Walmart" is being actively attacked by a ransomware campaign, or that its data has already been compromised and dumped publicly on the site.', 'cybersixgillrecommendations': '', 'cybersixgillstatus': 'In Treatment', 'cybersixgillsite': 'rw_everest', 'cybersixgillactor': None, 'cybersixgilltriggeredassets': ['Walmart']}, 'status': 1, 'details': 'A ransomware group posted on its leak site, rw_everest, focusing on "Walmart" \n\n\n\n', 'rawJSON': '{"additional_info": {"asset_attributes": ["organization_aliases", "domain_names"], "domain_names": ["bank.com", "nike.com", "cybersixgill.com", "meineschufa.de", "bank.com", "test.com", "eitan.com"], "matched_domain_names": [], "matched_organization_aliases": ["Walmart"], "organization_aliases": ["walmart", "cybersixgill", "nike"], "organization_name": "Cybersixgill", "post_attributes": ["site"], "query_attributes": ["organization_aliases", "domain_names"], "site": "rw_everest", "template_id": "5fd0d2acddd06410ac5348d1", "vendor": "Sixgill"}, "alert_id": "616ffed97a1b66036a138f73", "alert_name": "Your organization was potentially targeted by a ransomware group", "alert_type": "QueryBasedManagedAlertRule", "assessment": "This could indicate that \\"Walmart\\" is being actively attacked by a ransomware campaign, or that its data has already been compromised and dumped publicly on the site.", "category": "regular", "content_type": "search_result_item", "description": "A ransomware group posted on its leak site, rw_everest, focusing on \\"Walmart\\" ", "es_id": "51baa80bb1a01ba4b4a08f59a2313ff60e78bf75", "es_item": {}, "id": "6188bd21017198385e228437", "lang": "English", "langcode": "en", "read": true, "recommendations": [], "severity": 1, "site": "rw_everest", "status": {"name": "in_treatment", "user": "60b604a048ce2cb294629a2d"}, "summary": "", "threat_level": "imminent", "threats": ["Brand Protection", "Data Leak"], "title": "Your organization was potentially targeted by a ransomware group", "update_time": "2021-11-08 06:01:05", "user_id": "5d233575f8db38787dbe24b6", "date": "2021-11-08 06:01:05"}'}]



class MockedResponse(object):
    def __init__(self, status_code):
        self.status_code = status_code
        self.ok = True if self.status_code == 200 else False


def get_incidents_list():
    return copy.deepcopy(incidents_list)


def get_info_item():
    return copy.deepcopy(info_item)


def get_content_item():
    return copy.deepcopy(content_item)


def init_params():
    return {
        'client_id': 'WRONG_CLIENT_ID_TEST',
        'client_secret': 'CLIENT_SECRET_TEST',
    }


def test_test_module_raise_exception(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch('requests.sessions.Session.send', return_value=MockedResponse(400))

    from CybersixgillActionableAlerts import test_module

    with pytest.raises(Exception):
        test_module()


def test_test_module(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch('requests.sessions.Session.send', return_value=MockedResponse(200))

    from CybersixgillActionableAlerts import test_module
    test_module()


def test_fetch_incidents(mocker):
    mocker.patch.object(demisto, 'params', return_value=init_params())
    mocker.patch.object(demisto, 'last_fetch_time', return_value={'time': '2021-11-07 06:01:05'})
    mocker.patch.object(demisto, 'incidents')

    from sixgill.sixgill_alert_client import SixgillAlertClient

    mocker.patch.object(SixgillAlertClient, 'get_actionable_alerts_bulk', return_value=get_incidents_list())
    mocker.patch.object(SixgillAlertClient, 'get_actionable_alert', return_value=get_info_item())
    mocker.patch.object(SixgillAlertClient, 'get_actionable_alert_content', return_value=get_content_item())

    from CybersixgillActionableAlerts import fetch_incidents
    fetch_incidents()

    assert demisto.incidents.call_count == 1
    incidents = demisto.incidents.call_args[0][0]

    assert(len(incidents) == 6)
    assert (incidents == expected_alert_output)