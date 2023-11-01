function levenshtein(s1, s2) {
    const l1 = s1.length;
    const l2 = s2.length;

    // Initialize the matrix
    const matrix = Array.from({ length: l2 + 1 }, (_, i) => Array.from({ length: l1 + 1 }, (_, j) => (i === 0) ? j : i));

    // Populate the matrix
    for (let zz = 0; zz < l2; zz++) {
        for (let sz = 0; sz < l1; sz++) {
            if (s1[sz] === s2[zz]) {
                matrix[zz + 1][sz + 1] = Math.min(matrix[zz + 1][sz] + 1, matrix[zz][sz + 1] + 1, matrix[zz][sz]);
            } else {
                matrix[zz + 1][sz + 1] = Math.min(matrix[zz + 1][sz] + 1, matrix[zz][sz + 1] + 1, matrix[zz][sz] + 1);
            }
        }
    }

    // Return the result
    return matrix[l2][l1];
}

var email = args.email;
var domains = argToList(args.domain);
var threshold = parseInt(args.threshold);

var emailParts = email.split('@',2);

if (emailParts.length < 2){
    return {
        ContentsFormat: formats.text,
        Type: entryTypes.error,
        Contents: email.toString() + " - is not a valid email address"
    };
}
var emailObj = {
    Username: emailParts[0],
    Domain: emailParts[1],
    Address : email,
    Distance : []
};

domains.forEach(function(domain){
    if(domain) {
        let levenshteinForDomain = levenshtein(emailObj.Domain, domain.toLowerCase());
        emailObj.Distance.push(
            {
                Domain  : domain,
                Value   : levenshteinForDomain
            });
    }
});

var ec = {};
var suspicious = dq(emailObj,"Distance(val.Value > 0 && val.Value < {0}).Value".format(threshold));
var dbotScore = 0;
var malicious = null;

if(suspicious && suspicious.length > 0){
    //add dbot score, suspicious
    ec.DBotScore = {
        Indicator: email,
        Type: 'email',
        Vendor: 'DomainSquatting', Score: 2
    };
    //add suspicious description to the indicator
    malicious = {
        Vendor: "DomainSquatting",
        Description : "The email address domain is suspicious at domain squatting"
    };
}

var account = {Email: emailObj};
if (malicious){
    account.Malicious = malicious;
}

ec["Account(val.Email && val.Email.Address && val.Email.Address === obj.Email.Address)"] = account;

var md = tableToMarkdown("Domain squatting reputation for {0}".format(email),emailObj.Distance);

return {
    Type: entryTypes.note,
    Contents: emailObj,
    ContentsFormat: formats.json,
    HumanReadable: md,
    EntryContext: ec
};
