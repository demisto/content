var d = new Date();
if (args.date){
    if (args.date.length > 0){
        // args.date is string
        d =  new Date(args.date);
    } else {
        // args.date is object (Time.time in Go)
        d =  new Date(args.date.Unix()*1000);
    }
}
if (args.minutesAgo){
    d.setMinutes(d.getMinutes() - args.minutesAgo);
}
if (args.hoursAgo){
    d.setHours(d.getHours() - args.hoursAgo);
}
if (args.daysAgo){
    d.setDate(d.getDate() - args.daysAgo);
}
if (args.monthsAgo){
    d.setMonth(d.getMonth() - args.monthsAgo);
}
if (args.yearsAgo){
    d.setFullYear(d.getFullYear() - args.yearsAgo);
}

prefix = '';
if (args.contextKey) {
    prefix = args.contextKey;
}
var timeStr = String(d);
if ((args.dateFormat) && (args.dateFormat.length > 0)){
    switch(args.dateFormat.toLowerCase()) {
        case 'iso':
            timeStr = d.toISOString();
            break;
        case 'gmt':
        case 'utc':
            timeStr = d.toUTCString();
            break;
        case 'locale':
            timeStr = d.toLocaleString();
            break;
        case 'date':
            timeStr = d.toDateString();
            break;
        case 'year':
            timeStr = d.getFullYear();
            break;
        case 'month':
            timeStr = d.getMonth();
            break;
        case 'day':
            timeStr = d.getDate();
            break;
        case 'dayinweek':
            timeStr = d.getDay();
            break;
        case 'hours':
            timeStr = d.getHours();
            break;
        case 'utchours':
            timeStr = d.getUTCHours();
            break;
        case 'minutes':
            timeStr = d.getMinutes();
            break;


        default:
            throw 'Unsupported date format: '+args.dateFormat
    }
}

context = {};
context[prefix+'TimeNowUnix'] = d.getTime();
context[prefix+'TimeNow'] = timeStr;
return {
    Type : entryTypes.note,
    Contents : timeStr,
    ContentsFormat : formats.text,
    HumanReadable : timeStr,
    EntryContext : context
};
