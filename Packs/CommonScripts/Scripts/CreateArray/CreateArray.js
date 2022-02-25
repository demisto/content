var data = args.arrayData;
var seperator = ',';
if (args.separator){
    seperator = args.separator;
}
var contextKey = 'array';
if (args.contextKey){
    contextKey = args.contextKey;
}
var array = data.split(seperator);
for (var i=0; i<array.length; i++) {
    array[i]= array[i].trim();
}
var context = {};
context[contextKey] = array;
return {Type: entryTypes.note,
      Contents: JSON.stringify(array),
      ContentsFormat: formats.json,
      EntryContext: context
};
