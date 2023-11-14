function toBoolean(value) {
    if (typeof (value) === 'string') {
        if (['yes', 'true'].indexOf(value.toLowerCase()) != -1) {
            return true;
        } else if (['no', 'false'].indexOf(value.toLowerCase()) != -1) {
            return false;
        }
        throw 'Argument does not contain a valid boolean-like value';
    }
    return value ? true : false;
}


function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}


function main() {
    const email = args.email;
    const domains = argToList(JSON.stringify(args.domain)).map(x => x.toLowerCase());
    const includeSubdomains = toBoolean(args.include_subdomains);

    const parts = email.split('@', 2);

    let networkType = 'Unknown';
    let inDomain = 'no';

    if (parts.length > 1) {
        const domain = parts[1].toLowerCase();
        if (domains.includes(domain) || (includeSubdomains && new RegExp(`^(.*\\.)?(${domains.map(d => escapeRegex(d)).join('|')})`).test(domain))) {
            inDomain = 'yes';
            networkType = 'Internal';
        } else {
            networkType = 'External';
        }

        const emailDict = {
            'Address': email,
            'Domain': domain,
            'Username': parts[0],
            'NetworkType': networkType
        };

        const emailObj = {
            'Account.Email(val.Address && val.Address == obj.Address)': emailDict
        };

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': inDomain,
            'HumanReadable': inDomain,
            'EntryContext': emailObj
        };
    } else {
        return {
            Type: entryTypes.error,
            ContentsFormat: formats.text,
            Contents: `Email address "${email}" is not valid`
        };
    }
}

try {
    return main();
} catch (error) {
    throw 'Error occurred while running the script:\n' + error;
}
