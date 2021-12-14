var values = argToList(args.values);
var translated = argToList(args.translated);
var input = args.input.toLowerCase();

for (var i=0; i<values.length && i<translated.length; i++) {
    if (input === values[i].toLowerCase()) {
        return translated[i];
    }
}
return args.input;
