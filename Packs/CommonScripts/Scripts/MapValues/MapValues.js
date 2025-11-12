if (typeof args.input === 'object' && args.input !== null) {
    throw 'Input cannot be an object. Please provide a string or a number.';
}

var values = argToList(args.values);
var translated = argToList(args.translated);
var input = String(args.input).toLowerCase();

for (var i=0; i<values.length && i<translated.length; i++) {
    if (typeof values[i] === 'object' && values[i] !== null) {
        throw 'Values cannot contain objects. Please provide strings or numbers.';
    }
    if (input === String(values[i]).toLowerCase()) {
        return translated[i];
    }
}
return args.input;
