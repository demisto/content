var res = executeCommand("IsInCidrRanges", args)[0].Contents;
res = Array.isArray(res) ? res : [res];
return res.map(val => val == "True" ? "False" : "True");