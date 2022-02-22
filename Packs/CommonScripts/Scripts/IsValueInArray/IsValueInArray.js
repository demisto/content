var array = args.array;
var value = args.value;

if (!array || !value) {
  return 'no';
}

if (typeof array === 'string') {
    try {
        array = JSON.parse(array);
    } catch(e) {
        return (array === value) ? 'yes' : 'no';
    }
}

if (!Array.isArray(array)) {
  return (array === value) ? 'yes' : 'no';
}

var res = 'no';
value = value.toString();
array.forEach(function(item) {
  if (item.toString() === value) {
      res = 'yes';
  }
});

return res;
