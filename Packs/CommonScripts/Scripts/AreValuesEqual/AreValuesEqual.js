if (args.left === undefined || args.right === undefined) {
    return 'no';
}

var left = (typeof args.left === 'string') ? args.left : args.left + '';
var right = (typeof args.right === 'string') ? args.right : args.right + '';
var answer = 'no';
if (left === right) {
  answer = 'yes';
}

setContext('AreValuesEqual', answer)
return answer;
