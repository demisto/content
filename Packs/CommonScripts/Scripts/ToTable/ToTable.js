var data = args.data;
var headers = args.columns ? args.columns.split(',') : null;
if(!Array.isArray(data)) {
    data = [data]
}
var flatData = [];
data.forEach(function(element) {
  var flattenObject = treeToFlattenObject(element);
  flatData.push(flattenObject);
});
return {Type: entryTypes.note, Contents: tableToMarkdown(args.title, flatData, headers), ContentsFormat: formats.markdown};
