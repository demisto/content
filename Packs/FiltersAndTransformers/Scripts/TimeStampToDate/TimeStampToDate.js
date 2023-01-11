var value = parseInt(args.value)

// Add miliseconds if needed
if (value < 10000000000) {
    value *= 1000
}

var date =  new Date(value);
return date.toISOString();
