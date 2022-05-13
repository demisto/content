var scores = dq(invContext, 'DBotScore(val.Indicator && val.Score)'); if (!(Array.isArray(scores))) {
    scores = [scores]
}
var s = {};
for (i=0; i<scores.length; i++) {
    if (!s[scores[i].Indicator]) {
        s[scores[i].Indicator] = [];
    }
    s[scores[i].Indicator].push(scores[i].Score);
}
var avg = Object.keys(s).map(function(ind) {
    var sum = 0;
    s[ind].forEach(function(i) {sum += i;});
    return {Indicator: ind, Score: sum / s[ind].length};
});
return {Type: entryTypes.note, Contents: avg, ContentsFormat: formats.json, HumanReadable: 'Scores average calculated', EntryContext: {'DBotAvgScore(val.Indicator == obj.Indicator)': avg}};
