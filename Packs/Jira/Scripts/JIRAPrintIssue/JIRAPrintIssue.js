var response = executeCommand('jira-get-issue', { issueId: args.issueId });

if (!response || response.length === 0 || !response[0].Contents || isError(response[0])) {
    return 'JIRA issue not found (' + args.issueId + ')';
}

var issue = response[0].Contents;
var fields = issue.fields;

var id = issue.id;
var key = issue.key;
var url = issue.self;
var summary = fields.summary;
var description = fields.description;
var attachments = fields.attachment;
var comments = fields.comment && fields.comment.comments;
var project = fields.project.name;
var ticketStatus = fields.status.name;
var ticketStatusDesc = fields.status.description;
var created = fields.created;
var updated = fields.updated;
var closedTime = fields.resolutiondate;

var creator = {
    name: fields.creator.displayName,
    email: fields.creator.emailAddress,
    avatarUrl: fields.creator.avatarUrls['24x24'],
    url: fields.creator.self
};

var reporter = {
    name: fields.reporter.displayName,
    email: fields.reporter.emailAddress,
    avatarUrl: fields.reporter.avatarUrls['24x24'],
    url: fields.reporter.self
};

var md = '## JIRA Issue ' + key + ' - ' + summary + ' (' + ticketStatus + ')\n';
md += 'Opened by ' + creator.name + ' (' + creator.email + ') ![avatar](' + creator.avatarUrl+ '=size=24x24)\n\n';
md += '#### Status: \n' + ticketStatus + ' (' + ticketStatusDesc + ')\n';

md += '#### Timeline\n';
md += '- Created at ' + created + '\n';
if (updated) {
    md += '- Updated at ' + updated + '\n';
}
if (closedTime) {
    md += '- Closed at ' + closedTime + '\n';
}

if (attachments) {
    md += '#### Attachments (' + attachments.length + '):\n';
    attachments.map(function(att, i) {
        md += '\n**Attachment ' + (i + 1) + '** From: ' + att.author.displayName + ' (' + att.author.emailAddress + ') - ' + att.created + ':\n';
        md += '[' + att.filename + '](' + att.content + ') (' + att.mimeType + ') Size: ' + att.size;
        md += '\n\n --- \n\n';
    });
}

if (comments) {
    md += '#### Comments (' + comments.length + '):\n';
    comments.map(function(comment, i) {
        md += '\n**Comment ' + (i + 1) + '** From: ' + comment.author.displayName + ' (' + comment.author.emailAddress + ') - ' + comment.created + ':\n';
        md += comment.body;
        md += '\n\n --- \n\n';
    });
}

return { Type: entryTypes.note, Contents: issue, ContentsFormat: formats.json, HumanReadable: md };
