function levenshtein(str1, str2) {
    const len1 = str1.length;
    const len2 = str2.length;
    
    // Create a 2D array to store the edit distances
    const matrix = new Array(len1 + 1);
    for (let i = 0; i <= len1; i++) {
      matrix[i] = new Array(len2 + 1);
    }
  
    // Initialize the matrix
    for (let i = 0; i <= len1; i++) {
      matrix[i][0] = i;
    }
  
    for (let j = 0; j <= len2; j++) {
      matrix[0][j] = j;
    }
  
    // Fill in the matrix using dynamic programming
    for (let i = 1; i <= len1; i++) {
      for (let j = 1; j <= len2; j++) {
        const cost = (str1[i - 1] === str2[j - 1]) ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,       // Deletion
          matrix[i][j - 1] + 1,       // Insertion
          matrix[i - 1][j - 1] + cost // Substitution
        );
      }
    }
  
    // The final edit distance is in the bottom-right cell of the matrix
    return matrix[len1][len2];
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
