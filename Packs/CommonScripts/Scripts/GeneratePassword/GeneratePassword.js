dArgs = {
    'debug': args.debug = (args.debug === 'true'),
    'max_lcase': parseInt(args.max_lcase),
    'min_lcase': parseInt(args.min_lcase),
    'max_ucase': parseInt(args.max_ucase),
    'min_ucase': parseInt(args.min_lcase),
    'max_digits': parseInt(args.max_digits),
    'min_digits': parseInt(args.min_digits),
    'max_symbols': parseInt(args.max_symbols),
    'min_symbols': parseInt(args.min_symbols)
};

// randomize our selected charaters
function randomSort(a, b) {
    return Math.random() > 0.5 ? -1 : 1;
}

function printCharValues(pw) {
    var s = [];
    for (i = 0; i < pw.length; i++) {
        s.push(pw.charCodeAt(i));
    }
    log("Ascii for password = " + s.toString());
}

if(args.debug) {
   log(JSON.stringify(dArgs));
}

// Define the characters of our classes
var lcase   = "abcdefghijklmnopqrstuvwxyz";
var ucase   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
var n       = "0123456789";
var s       = "!@#$%^&*()[]+:\"?_><=';/-.,\\|";

// randomize the amount of characters we get as per parameters
var numu = dArgs.max_ucase   - dArgs.min_ucase   >= 0 ? Math.floor(Math.random() * (dArgs.max_ucase   - dArgs.min_ucase   + 1)) + dArgs.min_ucase   : 0;
var numl = dArgs.max_lcase   - dArgs.min_lcase   >= 0 ? Math.floor(Math.random() * (dArgs.max_lcase   - dArgs.min_lcase   + 1)) + dArgs.min_lcase   : 0;
var numn = dArgs.max_digits  - dArgs.min_digits  >= 0 ? Math.floor(Math.random() * (dArgs.max_digits  - dArgs.min_digits  + 1)) + dArgs.min_digits  : 0;
var nums = dArgs.max_symbols - dArgs.min_symbols >= 0 ? Math.floor(Math.random() * (dArgs.max_symbols - dArgs.min_symbols + 1)) + dArgs.min_symbols : 0;

if(numu + numl + numn + nums === 0) {
   return  { ContentsFormat: formats.text, Type:entryTypes.error, Contents: 'error: insane password. No character length.'};
}

// start with a blank password.
var pw = "";

// iterate through each character class and add
for (var i = 0; i < numu; i++) {
   pw += ucase[Math.floor(Math.random() * ucase.length)];
}
for (var i = 0; i < numl; i++) {
   pw += lcase[Math.floor(Math.random() * lcase.length)];
}
for (var i = 0; i < numn; i++) {
   pw += n[Math.floor(Math.random() * n.length)];
}
for (var i = 0; i < nums; i++) {
   pw += s[Math.floor(Math.random() * s.length)];
}

// randomize our new password string
var rpw = (pw.split('').sort(randomSort)).join('');

if(args.debug) {
    printCharValues(rpw);
}
return {
        Type: entryTypes.note,
        Contents: {"NEW_PASSWORD": rpw},          // used by raw_contents = true
        ContentsFormat: formats.json,             // defines the source format
        HumanReadable: tableToMarkdown('Newly Generated Password', {"password": rpw}),
        EntryContext: {"NEW_PASSWORD": rpw}       // same as setcontext
};

