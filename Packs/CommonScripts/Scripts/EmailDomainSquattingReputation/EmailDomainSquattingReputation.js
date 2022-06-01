
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
      var resp = executeCommand("GetStringsDistance", {inputString: emailObj.Domain, compareString: domain});

      if(isError(resp[0])){
          return resp;
      }

      data = [dq(resp[0], "Contents.Distances")];
      data.forEach(function(entry)
      {
          emailObj.Distance.push(
              {
                  Domain  : dq(entry,"StringB"),
                  Value   : dq(entry,"LevenshteinDistance")
              });
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
