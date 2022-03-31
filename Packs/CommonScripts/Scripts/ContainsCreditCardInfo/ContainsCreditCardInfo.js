var americanExpress = '(?:3[47][0-9]{13})';
var dinersClub = '(?:3(?:0[0-5]|[68][0-9])[0-9]{11})';
var discover = '(?:6(?:011|5[0-9]{2})(?:[0-9]{12}))';
var jcb = '(?:(?:2131|1800|35\\d{3})\\d{11})';
var maestro = '(?:(?:5[0678]\\d\\d|6304|6390|67\\d\\d)\\d{8,15})';
var mastercard = '(?:(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12})';
var visa = '(?:4[0-9]{12})(?:[0-9]{3})?';

var ccRegex = [americanExpress, dinersClub, discover, jcb, maestro, mastercard, visa];

for (var i=0; i<ccRegex.length; i++){
    var r = new RegExp(ccRegex[i]);
    var m = r.exec(args.data);
    if (m && m.length > 0) {
        return 'yes';
    }
}
return 'no';
