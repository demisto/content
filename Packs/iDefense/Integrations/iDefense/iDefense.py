 #var base_url = params.url.slice(0, params.url.length - params.url.match('/*$')[0].length) + '/rest/';


    def sendRequest(method, url_suffix, headers, body) :
        headers = headers or {}
        body = body or {}

        # // add default headers
        if (("Accept" not in headers)):
            headers["Accept"] = ['application/json']

        if (!("Content-Type" in headers)):
            headers['Content-Type'] = ['application/json']

        headers['Auth-Token'] = [params.api_token]

        res = http(
            base_url + url_suffix,
            {
                Method: method,
                Headers: headers,
                Body: JSON.stringify(body),
            },
            params.insecure,
            params.useproxy
        )

        if (res.StatusCode < 200 || res.StatusCode >= 300) :
            throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.'

        return res.Body.length !== 0 ? JSON.parse(res.Body) : {}



    def calculate_dbot_score(severity):
        # // Calculate score based on severity
        # // Dbot Score   | severity
        # //  0           | 0
        # //  1           | 1,2
        # //  2           | 3,4
        # //  3           | 5,6,7
        dbot_score = 0
        if (severity > 4) :
            dbot_score = 3
        elif (severity > 2):
            dbot_score = 2
        elif (severity > 0):
            dbot_score = 1
        else:
            dbot_score = 0


        return dbot_score


    def get_full_data(cmd_url, query, result_threshold):
        result_threshold = result_threshold || 300;
        query = query or {}

        results = []

        query.page = 1;

        res = sendRequest('GET', cmd_url + encodeToURLQuery(query))
        if (res.total_size === 0):
            break

        results = results.concat(res.results);
        ++query.page;
        while ((res.more) and (results.length < result_threshold))

        return results


    def check_threats(type, value, uniq_field, results):
        if (!results) :
            cmd_url = 'threatindicator/v0/' + type.toLowerCase()
            query = {'key.values' : value}
            results = get_full_data(cmd_url, query)

            if (results.length === 0):
                return {results:[], md : [], context: {}}

        dbot_context = []
        result_context = []
        md = []
        for (var i in results):
            r = results[i]
            dbot_score = calculate_dbot_score(r.severity)

            md.push({
                Name : r.key,
                'Dbot Reputation' : scoreToReputation(dbot_score),
                confidence : r.confidence,
                'Threat Types' : r.threat_types
            })

            dbot_context.push({
                Indicator : r.key,
                Type : type.toLowerCase(),
                Vendor : 'iDefense',
                Score : dbot_score
            })

            if (dbot_score >= 2):
                r_context = {
                    Malicious : {
                        Vendor : 'iDefense',
                        Description : 'last seen as ' + r.last_seen_as
                    }

                r_context[uniq_field] = r.key
                result_context.push(r_context)
            }


        context_type = type + '(val.' + uniq_field + ' && val.' + uniq_field + ' == obj.' + uniq_field + ')'
        context = {}
        if (result_context.length > 0) :
            context[context_type] = result_context;


        return {
            results : results,
            md : md,
            context : context,
            scores : dbot_context

        }


    def sort_threats(results):
        domains = [], urls = [], ips = [], others = []

        for (var i in results) {
            switch (results[i].type) {
            case 'domain':
                domains.push(results[i]);
                break;
            case 'ip':
                ips.push(results[i]);
                break;
            case 'url':
                urls.push(results[i]);
                break;
            default:
                others.push(results[i]);
            }
        }

        domain_threats = check_threats('Domain', undefined, 'Name', domains),
        ip_threats = check_threats('IP', undefined, 'Address', ips),
        url_threats = check_threats('URL', undefined, 'Data', urls)

        merged_md = domain_threats.md.concat(ip_threats.md).concat(url_threats.md)
        merged_scores = domain_threats.scores.concat(ip_threats.scores).concat(url_threats.scores)

        return {
            Type : entryTypes.note,
            Contents : results,
            ContentsFormat : formats.json,
            HumanReadable : tableToMarkdown('iDefense Reputations', merged_md),
            EntryContext : mergeForeignObjects([domain_threats.context, ip_threats.context, url_threats.context, {DBotScore : merged_scores}])
        }




    def get_threats(max_results):
        cmd_url = 'threatindicator/v0/'
        results = get_full_data(cmd_url, {}, max_results)

        return sort_threats(results);
    }


    def get_domain(domain):
        threats_info = check_threats('Domain', domain, 'Name')
        if (threats_info.results.length === 0):
            return 'No result was found.'

        return {
            Type : entryTypes.note,
            Contents : threats_info.results,
            ContentsFormat : formats.json,
            HumanReadable : tableToMarkdown('iDefense Domain Reputation', threats_info.md),
            EntryContext : mergeForeignObjects([threats_info.context, {DBotScore : threats_info.scores}])
        }



    def get_ip(ip):
        if (!isValidIP(ip)):
            return {Type: entryTypes.error, Contents: 'IP - ' + ip + ' is not valid IP', ContentsFormat: formats.text}


        threats_info = check_threats('IP', ip, 'Address')
        if (threats_info.results.length === 0):
            return 'No result was found.'


        return {
            Type : entryTypes.note,
            Contents : threats_info.results,
            ContentsFormat : formats.json,
            HumanReadable : tableToMarkdown('iDefense IP Reputation', threats_info.md),
            EntryContext : mergeForeignObjects([threats_info.context, {DBotScore : threats_info.scores}])

        }



    def get_url(url):
        var threats_info = check_threats('URL', url, 'Data');
        if (threats_info.results.length === 0):
            return 'No result was found.';


        return {
            Type : entryTypes.note,
            Contents : threats_info.results,
            ContentsFormat : formats.json,
            HumanReadable : tableToMarkdown('iDefense URL Reputation', threats_info.md),
            EntryContext : mergeForeignObjects([threats_info.context, {DBotScore : threats_info.scores}])

        }



    def get_uuid(uuid):
        cmd_url = 'threatindicator/v0/' + uuid
        res = sendRequest('GET', cmd_url)

        return sort_threats([res])



    # // The command input arg holds the command sent from the user.
    #
    # logDebug('entering with command: ' + command);
    #
    # switch (command) {
    #     case 'idefense-general':
    #         // still having issues with this command.
    #         return get_threats(args.max_result);
    #     case 'domain':
    #         return get_domain(args.domain);
    #     case 'ip':
    #         return get_ip(args.ip);
    #     case 'url':
    #         return get_url(args.url);
    #     case 'uuid':
    #         // still having issues with this command.
    #         return get_uuid(args.uuid);
    #     // This is the call made when pressing the integration test button.
    #     case 'test-module':
    #         //check api_token is valid
    #         get_threats(1);
    #         return 'ok';
    #     default:
    #         break;