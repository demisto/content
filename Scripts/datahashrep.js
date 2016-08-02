var xfeScore = -1;
var vtScore = -1;
var cyScore = -1;
var wfScore = -1;
var csScore = -1;
var rep = executeCommand('file', {file: args.input});
if (rep) {
  for (var r = 0; r < rep.length; r++) {
    if (rep[r].Type !== entryTypes.error && rep[r].ContentsFormat === formats.json) {
      if (rep[r].Brand === brands.xfe && rep[r].Contents && rep[r].Contents.malware.family) {
        xfeScore = 3;
      } else if (rep[r].Brand === brands.vt && rep[r].Contents && rep[r].Contents.positives) {
        var detected = rep[r].Contents.positives;
        if (detected > 15) {
          vtScore = 3;
        } else if (detected > 4) {
          vtScore = 2;
        } else {
          vtScore = 1;
        }
      } else if (rep[r].Brand === brands.cy && rep[r].Contents) {
        var k = Object.keys(rep[r].Contents);
        if (k && k.length > 0) {
          var v = rep[r].Contents[k[0]];
          if (v && v.generalscore) {
            var score = v.generalscore;
            if (score < -0.7) {
              cyScore = 3;
            } else if (score < -0.1) {
              cyScore = 2;
            } else {
              cyScore = 1;
            }
          }
        }
      } else if (rep[r].Brand === brands.wf && rep[r].Contents) {
        if (positiveFile(rep[r])) {
          wfScore = 3;
        }
      } else if (rep[r].Brand === brands.cs && rep[r].Contents && rep[r].Contents.length) {
        csScore = rep[r].Contents[0].malicious_confidence === 'high' ? 3 : rep[r].Contents[0].malicious_confidence === 'medium' ? 2 : 1;
      }
    }
  }
}

var score = Math.max(xfeScore, vtScore, cyScore, wfScore, csScore);
return score < 0 ? 0 : score;
