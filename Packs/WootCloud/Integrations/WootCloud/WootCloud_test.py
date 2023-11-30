from WootCloud import fetch_incidents, Client, fetch_single_alert

MOCK_URL = 'https://api_mock.wootcloud.com'
MOCK_START = '2019-06-25T08:00:00Z'
MOCK_END = '2019-06-27T08:00:00Z'

MOCK_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Host': 'api.wootuno.wootcloud.com'
}

MOCK_PKT_ALERT = {
    "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxXzEzMzIxNThfMDAwIiwidCI6IjIwMTktMDYtMjZUMjA6MjQ6MjZaIn0=",
    "timestamp": "2019-06-26T20:24:26Z",
    "severity": "warning",
    "category": "Adminstrator Privilege gain attempted",
    "signature": "ET POLICY IP Check Domain (whatismyip in HTTP Host)",
    "source": {
        "city": "Unknown",
        "continent": "Unknown",
        "country": "Unknown",
        "ip": "192.168.1.193",
        "latitude": -1,
        "longitude": -1,
        "mac": "cc:cc:cc:bc:7c:01",
        "network": "internal",
        "port": 61079,
        "state": "Unknown",
        "subnet": "192.168.1.0/24",
        "time_zone": "Unknown",
        "zip": "Unknown",
        "inferred": {
            "device_id": "5b4c3c91072c98142d308c31",
            "asset": "managed",
            "managed": "true",
            "category": "mobile_phone",
            "control": "user",
            "host_name": "Shahabs-iPhone",
            "os": "ios",
            "os_version": "12.1.4",
            "ownership": "corporate",
            "total_risk": 18.188051551163394,
            "type": "smart phone",
            "username": "",
            "managed_info": {
                "host_name": "Shahabs-iPhone"
            }
        }
    },
    "destination": {
        "city": "Cambridge",
        "continent": "North America",
        "country": "United States",
        "ip": "192.168.1.22",
        "latitude": 42.3626,
        "longitude": -71.0843,
        "mac": "cc:cc:cc:cc:c3:c0",
        "network": "external",
        "port": 80,
        "state": "Massachusetts",
        "subnet": "",
        "time_zone": "America/New_York",
        "zip": "02142",
        "inferred": {
            "device_id": "",
            "asset": "unmanaged",
            "managed": "false",
            "category": "",
            "control": "",
            "host_name": "",
            "os": "",
            "os_version": "",
            "ownership": "",
            "total_risk": 0,
            "type": "",
            "username": "",
            "managed_info": {
                "host_name": ""
            }
        }
    },
    "payload": ""
}


ANOMALY_ALERT = {
    "id": "eyJpIjoibWxub2RlX3AwMDhfY2F0LGY4OjJkOjdjOjJmOjQzOjdjLHVua==",
    "timestamp": "2019-05-02T08:00:00Z",
    "anomaly_type": "bytes_received",
    "signature": "60 (minutes) 'bytes_received'",
    "description": "Anomaly: 60 minutes unknown-protocol was significantly more than average during this time",
    "severity": "warning",
    "count": 1,
    "average": 0,
    "minimum": 0,
    "maximum": 0,
    "standard_deviation": 0,
    "anomaly_score": 1,
    "observed_value": 805,
    "deviation_from_norm": "8050.0",
    "units": "bytes",
    "address": "f8:2d:7c:2f:43:7c",
    "device_details": {
        "device_id": "5cc31d4b954fbc0e96c84eff",
        "asset": "unmanaged",
        "managed": "false",
        "category": "mobile_phone",
        "control": "user",
        "host_name": "iPhone",
        "os": "ios",
        "os_version": "",
        "ownership": "employee-owned",
        "total_risk": 0.008771929824570352,
        "type": "smart phone",
        "username": "",
        "managed_info": {
            "host_name": ""
        },
        "ip": "",
        "network": ""
    }
}


FETCH_ALERTS = {
    "total": 199,
    "packet_alerts": [
        {
            "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxXzEyNzY5XzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDAzMTQifQ==",
            "address": "7c:67:a2:37:77:51",
            "timestamp": "2020-03-14T03:00:27Z",
            "severity": "info",
            "category": "User Activity Detected",
            "signature": "ET POLICY Dropbox.com Offsite File Backup in Use",
            "source": {
                "city": "San Francisco",
                "continent": "North America",
                "country": "United States",
                "ip": "4.4.4.4",
                "latitude": 37.7697,
                "longitude": -122.3933,
                "mac": "c4:24:56:87:ef:11",
                "network": "external",
                "port": 443,
                "state": "California",
                "subnet": "",
                "time_zone": "America/Los_Angeles",
                "zip": "94107",
                "inferred": {
                    "device_id": "",
                    "asset": "unmanaged",
                    "managed": "false",
                    "category": "",
                    "control": "",
                    "host_name": "",
                    "os": "",
                    "os_version": "",
                    "ownership": "",
                    "total_risk": 0,
                    "type": "",
                    "username": "",
                    "managed_info": {
                        "host_name": ""
                    }
                }
            },
            "destination": {
                "city": "Unknown",
                "continent": "Unknown",
                "country": "Unknown",
                "ip": "2.2.2.2",
                "latitude": -1,
                "longitude": -1,
                "mac": "7c:67:a2:37:77:51",
                "network": "internal",
                "port": 54250,
                "state": "Unknown",
                "subnet": "10.10.10.10/24",
                "time_zone": "Unknown",
                "zip": "Unknown",
                "inferred": {
                    "device_id": "5b589f43e4b58d191f7e017c",
                    "asset": "managed",
                    "managed": "true",
                    "category": "computer",
                    "control": "user",
                    "host_name": "DESKTOP-73OV7ML",
                    "os": "windows",
                    "os_version": "10",
                    "ownership": "corporate",
                    "total_risk": 11.9,
                    "type": "computer",
                    "username": "7c67a2377751",
                    "managed_info": {
                        "host_name": "DESKTOP-73OV7ML"
                    }
                }
            },
            "payload": """....C...?..^lH.....b.R.]...?..J..~.^....Lr1...........
            .........#.......................0...0...........1.{....d.....\rR0\r
            ..*.H..\r.....0p1.0...U....US1.0...U.\n..Example Inc1.0...U....www.e
            xample.com1/0-..U...&Example SHA2 High Assurance Server CA0..\r18081
            6000000Z.\r201105120000Z0.1.0...U....US1.0...U...\nCalifornia1.0...U
            ...\rSan Francisco1.0...U.\n..Dropbox, Inc1.0...U....Dropbox Ops1.0.
            ..U...\r*.dropbox.com0..\"0\r..*.H..\r..........0..\n......1.$.#.jJ.
            .ZQ.6..ku47kS..i.\r<.9...\r3...v.(.....Q..7.\n{.....$.i.i...^1.g.A.)
            k......!Qq=.4.O:8k.+.(.-....-F1.U.9?|....I.....M..IA\n.I>.....'1....
            .....:]:.I.d..nn.7.g\".b11.....8.EJS5....1u..6x...x....q\n@.~...I!..
            .{~.u.nGk...CGr..^.y..l#...<x&V........J<.7..J..........v0..r0...U.#
            ..0...Qh.....u<..edb...Yr;0...U.......|...Xu3.z.R.RU..n8.0%..U....0.
            .\r*.dropbox.com..dropbox.com0...U...........0...U.%..0...+.........
            +.......0u..U...n0l04.2.0..http://crl3.example.com/sha2-ha-server-g6
            .crl04.2.0..http://crl4.example.com/sha2-ha-server-g6.crl0L..U. .E0C
            07..`.H...l..0*0(..+.........https://www.example.com/CPS0...g.....0.
            ...+........w0u0$..+.....0...http://ocsp.example.com0M..+.....0..Aht
            tp://cacerts.example.com/ExampleSHA2HighAssuranceServerCA.crt0...U..
            .....0.0....\n+.....y......o...k.i.w.......X......gp\n<5.......w...\
            r.....eC.s......H0F.!..Hv..,O._rd....g.C*......V..cw.e.!..6.-.......
            ..K<A\".[..=.........1.w..u..Y|..C._..n.V.GV6.J.`....^......eC.t....
            ..H0F.!..`.;.(,&.u.B.$S(...3..B#...X4....!.....X[.DPQ..YhW.....j...8
            ./\n.6...u.......q...#...{G8W.\n.R....d6.......eC.t......F0D. v.y7Gs
            .6Z..7(&(z..+t...w....tay.. _..6i........}6$...D..?7........0\r..*.H
            ..\r..........\r\"..R..IP..i.l...5.d..m.X.h#........9..T<...@...B.r.
            BK #...$..z/.. u....~I.r...._..{.0|12G..2.!...{...Z..C.. 7.....>...\
            n(F^..Y..z.H6..`9.....\\..\r{.[n2....I..........P.....+....~.......=
            .....p...b.`FpRr.E..u..s..TG...._..n.........|..Km..$/u..;rHLe....<.
            g.U...0...0...............\\..m.+B.]..0\r..*.H..\r.....0l1.0...U....
            US1.0...U.\n..Example Inc1.0...U....www.example.com1+0)..U...\"Examp
            le High Assurance EV Root CA0..\r131022120000Z.\r281022120000Z0p1.0.
            ..U....US1.0...U.\n..Example Inc1.0...U....www.example.com1/0-..U...
            &Example SHA2 High Assurance Server CA0..\"0\r..*.H..\r..........0..
            \n......./.$..m._..\nd..}\"&e..B@.....v.>.0U...O..Z..UV...*.....@...
            ;r............C:.......@....M._W..Ph................-..........^DX*7
            ..5...'2Z......Q.'..;B3..(..(...+#\rx.{.^q.J>........#.M.....u......
            .D5e.S%9..\n.c...th\n7..RH.9Z...]... .!..&o.J!A..m..H/....h.S/^.....
            ....I0..E0...U.......0.......0...U...........0...U.%..0...+.........
            +.......04..+........(0&0$..+.....0...http://ocsp.example.com0K..U..
            .D0B0@.>.<.:http://crl4.example.com/ExampleHighAssuranceEVRootCA.crl
            0=..U. .60402..U. .0*0(..+.........https://www.example.com/CPS0...U.
            .....Qh.....u<..edb...Yr;0...U.#..0....>.i...G...&....cd+.0\r..*.H..
            \r................m.\\..h.J...Q/.kD...c..nl.....q.[.4N..y.).-.j.. .y
            ...G.....Yq}...k.YX=..1%\\.8.......[.1N.x.....I..'..r.>..A...6...nGI
            .^.H|....I..&B@.....d\nWT.....^k......r.V....0..0...N.W..$...+..u..-
            ..}y'............ (AYC(......{;redacted>..3.g.a.r..i...W@.p........*
            ...&... P..y&.U......0.....],..i...E.1@{...........\n...J.c32NO...j.
            .'S7.N.in..,Q..[..~..eI#.w.O5./....G.M:..z.*..;`-....s'A.<Ce.;5\rE!.
            (..\ng|TY.\r..RX..Db.,*.~...D...`...:Om....Pr6..(w@....w..$.GB7.Um..
            .......X5....b......y).......C..2...../.W#.....Z....h\r..C....5^....
            ........AZ.....tw...).L..8b.............""",
            "http": "null",
            "type": "pkt_alert",
            "group": "alert",
            "subtype": "policy-violation",
            "title": "User Activity Detected",
            "description": "ET POLICY Dropbox.com Offsite File Backup in Use",
            "references": [
                "www.dropbox.com",
                "dereknewton.com/2011/04/dropbox-authentication-static-host-ids/"
            ]
        },
        {
            "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxXzEwOTAxXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDAzMTMifQ==",
            "address": "7c:67:a2:37:77:51",
            "timestamp": "2020-03-13T23:46:14Z",
            "severity": "info",
            "category": "User Activity Detected",
            "signature": "ET POLICY Dropbox.com Offsite File Backup in Use",
            "source": {
                "city": "San Francisco",
                "continent": "North America",
                "country": "United States",
                "ip": "4.4.4.4",
                "latitude": 37.7697,
                "longitude": -122.3933,
                "mac": "c4:24:56:87:ef:11",
                "network": "external",
                "port": 443,
                "state": "California",
                "subnet": "",
                "time_zone": "America/Los_Angeles",
                "zip": "94107",
                "inferred": {
                    "device_id": "",
                    "asset": "unmanaged",
                    "managed": "false",
                    "category": "",
                    "control": "",
                    "host_name": "",
                    "os": "",
                    "os_version": "",
                    "ownership": "",
                    "total_risk": 0,
                    "type": "",
                    "username": "",
                    "managed_info": {
                        "host_name": ""
                    }
                }
            },
            "destination": {
                "city": "Unknown",
                "continent": "Unknown",
                "country": "Unknown",
                "ip": "2.2.2.2",
                "latitude": -1,
                "longitude": -1,
                "mac": "7c:67:a2:37:77:51",
                "network": "internal",
                "port": 54131,
                "state": "Unknown",
                "subnet": "10.10.10.10/24",
                "time_zone": "Unknown",
                "zip": "Unknown",
                "inferred": {
                    "device_id": "5b589f43e4b58d191f7e017c",
                    "asset": "managed",
                    "managed": "true",
                    "category": "computer",
                    "control": "user",
                    "host_name": "DESKTOP-73OV7ML",
                    "os": "windows",
                    "os_version": "10",
                    "ownership": "corporate",
                    "total_risk": 11.9,
                    "type": "computer",
                    "username": "7c67a2377751",
                    "managed_info": {
                        "host_name": "DESKTOP-73OV7ML"
                    }
                }
            },
            "payload": """....C...?..^l.Fy.5.7.k..t..............:..............
            .........#.......................0...0...........1.{....d.....\rR0\r
            ..*.H..\r.....0p1.0...U....US1.0...U.\n..Example Inc1.0...U....www.e
            xample.com1/0-..U...&Example SHA2 High Assurance Server CA0..\r18081
            6000000Z.\r201105120000Z0.1.0...U....US1.0...U...\nCalifornia1.0...U
            ...\rSan Francisco1.0...U.\n..Dropbox, Inc1.0...U....Dropbox Ops1.0.
            ..U...\r*.dropbox.com0..\"0\r..*.H..\r..........0..\n......1.$.#.jJ.
            .ZQ.6..ku47kS..i.\r<.9...\r3...v.(.....Q..7.\n{.....$.i.i...^1.g.A.)
            k......!Qq=.4.O:8k.+.(.-....-F1.U.9?|....I.....M..IA\n.I>.....'1....
            .....:]:.I.d..nn.7.g\".b11.....8.EJS5....1u..6x...x....q\n@.~...I!..
            .{~.u.nGk...CGr..^.y..l#...<x&V........J<.7..J..........v0..r0...U.#
            ..0...Qh.....u<..edb...Yr;0...U.......|...Xu3.z.R.RU..n8.0%..U....0.
            .\r*.dropbox.com..dropbox.com0...U...........0...U.%..0...+.........
            +.......0u..U...n0l04.2.0..http://crl3.example.com/sha2-ha-server-g6
            .crl04.2.0..http://crl4.example.com/sha2-ha-server-g6.crl0L..U. .E0C
            07..`.H...l..0*0(..+.........https://www.example.com/CPS0...g.....0.
            ...+........w0u0$..+.....0...http://ocsp.example.com0M..+.....0..Aht
            tp://cacerts.example.com/ExampleSHA2HighAssuranceServerCA.crt0...U..
            .....0.0....\n+.....y......o...k.i.w.......X......gp\n<5.......w...\
            r.....eC.s......H0F.!..Hv..,O._rd....g.C*......V..cw.e.!..6.-.......
            ..K<A\".[..=.........1.w..u..Y|..C._..n.V.GV6.J.`....^......eC.t....
            ..H0F.!..`.;.(,&.u.B.$S(...3..B#...X4....!.....X[.DPQ..YhW.....j...8
            ./\n.6...u.......q...#...{G8W.\n.R....d6.......eC.t......F0D. v.y7Gs
            .6Z..7(&(z..+t...w....tay.. _..6i........}6$...D..?7........0\r..*.H
            ..\r..........\r\"..R..IP..i.l...5.d..m.X.h#........9..T<...@...B.r.
            BK #...$..z/.. u....~I.r...._..{.0|12G..2.!...{...Z..C.. 7.....>...\
            n(F^..Y..z.H6..`9.....\\..\r{.[n2....I..........P.....+....~.......=
            .....p...b.`FpRr.E..u..s..TG...._..n.........|..Km..$/u..;rHLe....<.
            g.U...0...0...............\\..m.+B.]..0\r..*.H..\r.....0l1.0...U....
            US1.0...U.\n..Example Inc1.0...U....www.example.com1+0)..U...\"Examp
            le High Assurance EV Root CA0..\r131022120000Z.\r281022120000Z0p1.0.
            ..U....US1.0...U.\n..Example Inc1.0...U....www.example.com1/0-..U...
            &Example SHA2 High Assurance Server CA0..\"0\r..*.H..\r..........0..
            \n......./.$..m._..\nd..}\"&e..B@.....v.>.0U...O..Z..UV...*.....@...
            ;r............C:.......@....M._W..Ph................-..........^DX*7
            ..5...'2Z......Q.'..;B3..(..(...+#\rx.{.^q.J>........#.M.....u......
            .D5e.S%9..\n.c...th\n7..RH.9Z...]... .!..&o.J!A..m..H/....h.S/^.....
            ....I0..E0...U.......0.......0...U...........0...U.%..0...+.........
            +.......04..+........(0&0$..+.....0...http://ocsp.example.com0K..U..
            .D0B0@.>.<.:http://crl4.example.com/ExampleHighAssuranceEVRootCA.crl
            0=..U. .60402..U. .0*0(..+.........https://www.example.com/CPS0...U.
            .....Qh.....u<..edb...Yr;0...U.#..0....>.i...G...&....cd+.0\r..*.H..
            \r................m.\\..h.J...Q/.kD...c..nl.....q.[.4N..y.).-.j.. .y
            ...G.....Yq}...k.YX=..1%\\.8.......[.1N.x.....I..'..r.>..A...6...nGI
            .^.H|....I..&B@.....d\nWT.....^k......r.V....0..0...N.W..$...+..u..-
            ..}y'............ (AYC(......{;redacted>..3.g.a.r..i...W@.p........*
            ...&... .wf.\n$2..[..@&km...7m...~.B.......@8^.t.,..;.;...D..2..G'..
            .G\"...=..E\\..44.........J.R+....Ms.c.w......%J.(K.gl.;\\.....Um..Z
            ....kR)...m[...N..k...&..D<.Y.\".....K...\n.......J.&.S{rX...5.H...#
            >.`8-G....7..s..@...q^... .Y.....*dHW......:.....7..|.(...O..c.r^..I
            ct..........5......x...G...\\h.B..........""",
            "http": "null",
            "type": "pkt_alert",
            "group": "alert",
            "subtype": "policy-violation",
            "title": "User Activity Detected",
            "description": "ET POLICY Dropbox.com Offsite File Backup in Use",
            "references": [
                "www.dropbox.com",
                "dereknewton.com/2011/04/dropbox-authentication-static-host-ids/"
            ]
        },
        {
            "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxXzk2MTlfMDAwIiwieCI6IjVhMDBiMTc1OWM3OTY0ODgwZmExYzFhNl9jX2QyMDIwMDMxMyJ9",
            "address": "34:f6:4b:b9:97:4a",
            "timestamp": "2020-03-13T22:14:32Z",
            "severity": "medium",
            "category": "User Activity Detected",
            "signature": "ET POLICY Cloudflare DNS Over HTTPS Certificate Inbound",
            "source": {
                "city": "Unknown",
                "continent": "North America",
                "country": "United States",
                "ip": "2.2.2.2",
                "latitude": 37.751,
                "longitude": -97.822,
                "mac": "c4:24:56:87:ef:11",
                "network": "external",
                "port": 443,
                "state": "Unknown",
                "subnet": "",
                "time_zone": "Unknown",
                "zip": "Unknown",
                "inferred": {
                    "device_id": "",
                    "asset": "unmanaged",
                    "managed": "false",
                    "category": "",
                    "control": "",
                    "host_name": "",
                    "os": "",
                    "os_version": "",
                    "ownership": "",
                    "total_risk": 0,
                    "type": "",
                    "username": "",
                    "managed_info": {
                        "host_name": ""
                    }
                }
            },
            "destination": {
                "city": "Unknown",
                "continent": "Unknown",
                "country": "Unknown",
                "ip": "4.4.4.4",
                "latitude": -1,
                "longitude": -1,
                "mac": "34:f6:4b:b9:97:4a",
                "network": "internal",
                "port": 56402,
                "state": "Unknown",
                "subnet": "10.10.10.10/24",
                "time_zone": "Unknown",
                "zip": "Unknown",
                "inferred": {
                    "device_id": "5a0b2a3eccd47205deb12fb3",
                    "asset": "managed",
                    "managed": "true",
                    "category": "computer",
                    "control": "user",
                    "host_name": "DESKTOP-BEJRPN4",
                    "os": "windows",
                    "os_version": "10",
                    "ownership": "corporate",
                    "total_risk": 0.11,
                    "type": "computer",
                    "username": "sakella",
                    "managed_info": {
                        "host_name": "DESKTOP-BEJRPN4"
                    }
                }
            },
            "payload": """....L...H..^l....?B....e....I.BP...DOWNGRD...+.. .....
            ...............#.........h2...............0...0..L.............V..+$
            .....0\n..*.H.=...0L1.0...U....US1.0...U.\n..Example Inc1&0$..U....E
            xample ECC Secure Server CA0..\r190128000000Z.\r210201120000Z0r1.0..
            .U....US1.0...U...\nCalifornia1.0...U...\rSan Francisco1.0...U.\n..C
            loudflare, Inc.1.0...U....cloudflare-dns.com0Y0...*.H.=....*.H.=....
            B... p. BP(.}DA|0y).c^.D...q:+.....l=j.w....PS...&.a7......].~....t.
            ...0...0...U.#..0.........9O.n......1.\n.0...U......p..\\..f........
            ..E..0....U.....0....cloudflare-dns.com..*.cloudflare-dns.com..one.o
            ne.one.one.................5..&.G.G.............&.G.G.............&.
            G.G..........d..&.G.G.........d.....$.......0...U...........0...U.%.
            .0...+.........+.......0i..U...b0`0..,.*.(http://crl3.example.com/ss
            ca-ecc-g1.crl0..,.*.(http://crl4.example.com/ssca-ecc-g1.crl0L..U. .
            E0C07..`.H...l..0*0(..+.........https://www.example.com/CPS0...g....
            .0{..+........o0m0$..+.....0...http://ocsp.example.com0E..+.....0..9
            http://cacerts.example.com/ExampleECCSecureServerCA.crt0...U.......0
            .0..~.\n+.....y......n...j.h.v.......X......gp\n<5.......w...\r.....
            h.........G0E.!.....1{E..2.[4z......Mq...t.fA1H.. p...T..l..g..6I...
            .F....o....1.J.u..u..Y|..C._..n.V.GV6.J.`....^......h...l.....F0D. P
            ..BL......B'1w.e..;..?.M#..\\.... ...'..b2...Ht.d. .Mn&.3...E..C...w
            .......q...#...{G8W.\n.R....d6.......h.........H0F.!...=0s9.R......0
            ...!P...L....Sp...!....?=?.Aq..;..\nv...]a.#.3f.c....0\n..*.H.=....h
            .0e.0{>..}.L.....F..vehk.zeQ.....N...{.^.4.>.......U..1..G.....';.X.
            .p.,.:p.Vo7.....?...^ ..c8.O@.m........0...0..........\n.(.F^.9.vtp.
            ...0\r..*.H..\r.....0a1.0...U....US1.0...U.\n..Example Inc1.0...U...
            .www.example.com1 0...U....Example Global Root CA0..\r130308120000Z.
            \r230308120000Z0L1.0...U....US1.0...U.\n..Example Inc1&0$..U....Exam
            ple ECC Secure Server CA0v0...*.H.=....+...\".b....B.w.$..,d...@.#r.
            .\n.7?!6..S.....K....q......^....Z...So...?..[?G$......./.W..q..x:..
            [<kd.+.4+....!0...0...U.......0.......0...U...........04..+........(
            0&0$..+.....0...http://ocsp.example.com0B..U...;0907.5.3.1http://crl
            3.example.com/ExampleGlobalRootCA.crl0=..U. .60402..U. .0*0(..+.....
            ....https://www.example.com/CPS0...U............9O.n......1.\n.0...U
            .#..0.....P5V.L.f........=.U0\r..*.H..\r.............CK.t.....056n.V
            {H..c.{.W$W.o...m........sd...7\n.I.?.&... ....*.f7.0...$.EH-..PJ1..
            .._.*.I<a.y..f...*.{6X.,A.t...H.....Eq3.0zz.!.$..........j.w.5...'d.
            C...wV....G.._(..hL..`...y.jv&... ..>.z(edf.....t.nM}........N..U..8
            .4...?..Oj.t./*.s._..C.l.}...\".O..w....s...o... ...i)..8.I.bD.....q
            <...].......S...G0E. p....#..u.._l.>..3xb.FV......{...!........\"...
            ...{_&k.d....!...n..#.........""",
            "http": "null",
            "type": "pkt_alert",
            "group": "alert",
            "subtype": "policy-violation",
            "title": "User Activity Detected",
            "description": "ET POLICY Cloudflare DNS Over HTTPS Certificate Inbound",
            "references": [
                "developers.cloudflare.com/1.1.1.1/dns-over-https/request-structure/"
            ]
        }
    ]
}


def test_first_fetch_incidents(requests_mock, mocker):
    client = Client(MOCK_URL + '/v1/', verify=True, headers=MOCK_HEADERS, auth=('test_user', 'test123'))
    requests_mock.post(MOCK_URL + '/v1/events/packetalerts', json=FETCH_ALERTS)
    fetch_incidents(client, 'packet')


def test_fetch_single_alert(requests_mock):
    ID = 'eyJpIjoiU05XT09UQVBQUFJPRDAxXzEzMzIxNThfMDAwIiwidCI6IjIwMTktMDYtMjZUMjA6MjQ6MjZaIn0='
    requests_mock.get(MOCK_URL + '/v1/events/packetalerts/' + ID, json=MOCK_PKT_ALERT)
    client = Client(MOCK_URL + '/v1/', verify=True, headers=MOCK_HEADERS, auth=('test_user', 'test123'))
    alert_type = "packet"
    assert fetch_single_alert(client, ID, alert_type).raw_response == MOCK_PKT_ALERT


def test_get_woot_alerts(requests_mock):
    client = Client(MOCK_URL + '/v1/', verify=True, headers=MOCK_HEADERS, auth=('test_user', 'test123'))
    requests_mock.post(MOCK_URL + '/v1/events/anomalies', json=ANOMALY_ALERT)
    assert client.get_woot_alerts('anomaly', MOCK_START, MOCK_END, limit='1').raw_response == ANOMALY_ALERT
