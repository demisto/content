import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Append this to CommonServerUserPython

from types import FrameType
from typing import List
from collections import OrderedDict
from datetime import datetime


EXCLUDELIST = [
    "iterencode",
    "dump",
    "dumps",
    "loads",
    "decode",
    "encode",
    "raw_decode",
    "append",
    "len",
    "strip",
    "split",
    "get_token",
    "parse",
    "now",
    "timestamp",
    "strftime",
    "sub",
    "compile"
]

SILENTLIST = [
    "executeCommand",
    "args",
    "incident",
    "incidents",
    "context",
    "error",
    "is_error",
    "isError",
    "getError",
    "return_error",
    "return_results",
    "CommandResults",
    "execute_command",
    "results",
    "fileResult"
]


def SdbgDictMarkdown(nested, indent: str) -> str:
    md = ""
    indent += "&nbsp;&nbsp;&nbsp;&nbsp;"
    if isinstance(nested, dict):
        for key, val in nested.items():
            if isinstance(val, dict):
                md += f"{indent} {key}\n"
                md += SdbgDictMarkdown(val, indent)
            elif isinstance(val, list):
                md += f"{indent} {key}\n"
                md += SdbgDictMarkdown(val, indent)
            else:
                md += f"{indent} {key}: {val}\n"
    elif isinstance(nested, list):
        for val in nested:
            if isinstance(val, dict):
                md += SdbgDictMarkdown(val, indent)
            elif isinstance(val, list):
                md += f"{indent} {val}\n"
                md += SdbgDictMarkdown(val, indent)
            else:
                md += f"{indent} {val}\n"
    else:
        md += f"{indent} {nested}\n"
    return md


class SimpleDebugger:
    def __init__(self):
        self.incid = ""
        self.code = OrderedDict()
        self.data = {}
        self.indent = ""
        self.currfunc = {}
        self.output = ""
        self.stepmode = False
        self.quietmode = False
        self.profmode = False
        self.logmode = True
        self.stack = []
        self.profile = {}
        self.excdepth = 0
        self.linebreak = []
        self.funcbreak = []
        self.printfunc = []
        self.prevlineno = 0
        self.lastcheck = 0
        self.exclude = EXCLUDELIST
        self.silent = SILENTLIST

        execute_command("setIncident", {
            'simpledebuggeroutput': " ",
            'simpledebuggercode': " ",
            'simpledebuggerdata': " ",
            'simpledebuggercmd': ""
        })
        self.SdbgLoadCommands()
        self.incid = demisto.incident()['id']

    def SdbgTraceOn(self):
        sys.settrace(self.SdbgTrace)

    def SdbgTraceOff(self):
        sys.settrace(None)

    def SdbgLoadCommands(self):
        fields = demisto.incident()['CustomFields']
        if 'simpledebuggerinput' in fields:
            lines = fields['simpledebuggerinput'].split("\n")
            for line in lines:
                if line.strip() == "":
                    continue
                cmd = line.split(" ", 1)
                command = cmd[0].strip()
                if command == "break":          # break lineno1, lineno2, func1, func2, ...
                    self.SdbgSetBreakpoint(cmd[1].split(","))
                elif command == "print":        # print func, func.var1, func.var2, ...
                    self.SdbgSetPrint(cmd[1].split(","))
                elif command == "quiet":        # quiet
                    self.quietmode = True
                elif command == "profile":      # profile
                    self.profmode = True
                elif command == "nolog":        # nolog
                    self.logmode = False
                elif command == "silent":
                    self.SdbgSetSilent(cmd[1].split(","))
                elif command == "exclude":
                    self.SdbgSetExclude(cmd[1].split(","))

    def SdbgSetBreakpoint(self, breakpoints):
        for b in breakpoints:
            if b.strip().isdigit():
                self.linebreak.append(int(b))
            else:
                self.funcbreak.append(b.strip())

    def SdbgSetPrint(self, functions: List[str]):
        for f in functions:
            self.printfunc.append(f.strip())

    def SdbgSetSilent(self, functions: List[str]):
        for f in functions:
            self.silent.append(f.strip())

    def SdbgSetExclude(self, functions: List[str]):
        for f in functions:
            self.exclude.append(f.strip())

    def SdbgLog(self, message: str):
        if self.logmode:
            time_ms = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            self.output = f"{time_ms} | {message}\n" + self.output
            execute_command("setIncident", {'simpledebuggeroutput': self.output})

    def SdbgCodeMd(self):
        markdown = ""
        for key, val in self.code.items():
            markdown += f"{val}\n"
        return markdown

    def SdbgDataMd(self, data):
        md = f"{self.currfunc['name']}():\n"
        md += SdbgDictMarkdown(data, "")
        return md

    def SdbgPrintLocals(self):
        execute_command("setIncident", {'simpledebuggerdata': self.SdbgDataMd(self.data[self.currfunc['name']])})

    def SdbgPrintCode(self):
        execute_command("setIncident", {'simpledebuggercode': self.SdbgCodeMd()})

    def SdbgPrintFunc(self, funclist: str):
        md = ""
        funcs = funclist.split(",")
        for ff in funcs:
            fv = ff.split(".")
            fname = fv[0].strip()
            if fname in self.data:
                if len(fv) == 1:
                    md += f"{fname}():\n"
                    md += SdbgDictMarkdown(self.data[fname], "")
                elif fv[1].strip() in self.data[fname]:
                    md += f"{fname}():\n"
                    vname = fv[1].strip()
                    value = {vname: self.data[fname][vname]}
                    md += SdbgDictMarkdown(value, "")
        if md != "":
            execute_command("setIncident", {'simpledebuggerdata': md})

    def SdbgPrintProfile(self):
        markdown = "|Function|Count|Average Duration|\n"
        markdown += "|:---|:---|:---|\n"
        for key, val in self.profile.items():
            markdown += f"|{key}|{val['count']}|{round(val['duration']/val['count'], 3)}|\n"
        execute_command("setIncident", {'simpledebuggerdata': markdown})

    def SdbgProfileEvent(self, frame: FrameType, event: str):
        if event == "call":
            if frame.f_code.co_name not in self.profile:
                self.profile[frame.f_code.co_name] = {
                    'count': 0,
                    'duration': 0.0,
                    'starts': []
                }
            self.profile[frame.f_code.co_name]['starts'].append(time.time())
        elif event == "return":
            start = self.profile[frame.f_code.co_name]['starts'].pop()
            self.profile[frame.f_code.co_name]['count'] += 1
            self.profile[frame.f_code.co_name]['duration'] += time.time() - start

    def SdbgTraceCall(self, frame: FrameType, event: str) -> str:
        self.SdbgLog(f"Called > {frame.f_code.co_name}")
        self.currfunc = {"name": frame.f_code.co_name, "lineno": frame.f_lineno}
        self.stack.append(self.currfunc)
        self.data[self.currfunc['name']] = {}
        c = f"_{frame.f_lineno}:[0] {self.indent}> {frame.f_code.co_name}("
        for i in range(frame.f_code.co_argcount):
            if i > 0:
                c += ", "
            name = frame.f_code.co_varnames[i]
            c += name
        c += ")_"
        self.indent += "    "
        return c

    def SdbgTraceReturn(self, frame: FrameType, event: str) -> str:
        self.SdbgLog(f"Return < {frame.f_code.co_name}")
        self.SdbgPrintFunc(",".join(self.printfunc))
        c = f"{frame.f_lineno}:[{frame.f_lineno - self.currfunc['lineno']}] {self.indent}< {frame.f_code.co_name}()"
        self.indent = self.indent.replace("    ", "", 1)
        self.stack.pop()
        if len(self.stack) > 0:
            self.currfunc = self.stack[-1]
        return c

    def SdbgTraceLine(self, frame: FrameType, event: str) -> str:
        c = f"**{frame.f_lineno}:[{frame.f_lineno - self.currfunc['lineno']}] {self.indent} {frame.f_code.co_name}()**"
        self.data[self.currfunc['name']] = frame.f_locals
        return c

    def SdbgSetCurrentLineno(self, frame: FrameType, c: str) -> bool:
        newcode = False
        if frame.f_lineno not in self.code:
            self.code[frame.f_lineno] = c
            self.code = OrderedDict(sorted(self.code.items()))
            newcode = True
        else:
            self.code[frame.f_lineno] = c
        if self.prevlineno != 0:
            self.code[self.prevlineno] = self.code[self.prevlineno].lstrip("**").rstrip("**")
        self.prevlineno = frame.f_lineno
        return newcode

    def SdbgCommand(self, frame: FrameType, breakpnt: bool) -> bool:
        if breakpoint is False:
            return False
        fields = execute_command("getIncidents", {"id": self.incid})['data'][0]['CustomFields']
        cmd = fields['simpledebuggercmd'].split(" ", 1)
        command = cmd[0].strip()
        if command == "continue":
            self.SdbgLog("Continue execution")
            self.stepmode = False
            breakpnt = False
        elif command == "step":
            self.stepmode = True
            breakpnt = False
        elif command == "print":
            self.SdbgLog(f"Print {cmd[1]}")
            self.SdbgPrintFunc(cmd[1])
        elif command == "stop":
            self.SdbgLog("Stop debugger and exit")
            self.SdbgTraceOff()
            sys.exit()
        elif command == "break":
            self.SdbgLog("Setting breakpoints")
            self.SdbgSetBreakpoint(cmd[1].split(","))
        elif command == "nolog":
            self.logmode = False
        elif command == "log":
            self.logmode = True

        execute_command("setIncident", {'simpledebuggercmd': ""})
        return breakpnt

    def SdbgException(self):
        self.SdbgLog(f"Exception thrown at line: {self.code[self.prevlineno].replace(' ', '')}, printing local variables")
        self.SdbgPrintLocals()
        self.SdbgTraceOff()

    def SdbgBreak(self, frame: FrameType, event: str) -> bool:
        if frame.f_lineno in self.linebreak:
            self.SdbgLog(f"Breakpoint at line > {frame.f_lineno}")
            return True
        if event == "call" and frame.f_code.co_name in self.funcbreak:
            self.SdbgLog(f"Breakpoint at function > {frame.f_code.co_name}")
            return True
        if self.stepmode:
            return True
        return False

    def SdbgExclude(self, frame: FrameType, event: str) -> bool:
        if frame.f_code.co_name in self.silent and event == "line":
            return True
        if frame.f_code.co_name in self.exclude:
            return True
        if frame.f_code.co_name.startswith("_"):
            return True
        if frame.f_code.co_name.startswith("<"):
            return True
        if frame.f_code.co_name.startswith("Sdbg"):
            return True
        return False

    def SdbgTrace(self, frame: FrameType, event: str, _arg: Any):
        if event == "exception":
            self.SdbgException()
            return None
        if self.SdbgExclude(frame, event):
            if event == "call":
                self.excdepth += 1
            elif event == "return":
                self.excdepth -= 1
            return self.SdbgTrace
        if self.excdepth > 0:
            return self.SdbgTrace

        if breakpnt := self.SdbgBreak(frame, event):
            self.SdbgPrintLocals()
            count = 0
            while breakpnt:
                breakpnt = self.SdbgCommand(frame, breakpnt)
                if not breakpnt:
                    break
                time.sleep(1.0)
                count += 1
                if count > 300:
                    self.SdbgLog("Timeout waiting for continue command, abandoning breakpoint")
                    break
        elif self.lastcheck == 20:
            self.SdbgCommand(frame, breakpnt)
            self.lastcheck = 0
        else:
            self.lastcheck += 1

        c = f"_{frame.f_lineno}: {self.indent}{event} {frame.f_code.co_name}"
        if event == "call":
            c = self.SdbgTraceCall(frame, event)
        elif event == "line":
            c = self.SdbgTraceLine(frame, event)
        elif event == "return":
            c = self.SdbgTraceReturn(frame, event)
        newcode = self.SdbgSetCurrentLineno(frame, c)

        if self.profmode:
            self.SdbgProfileEvent(frame, event)

        if newcode or not self.quietmode:
            self.SdbgPrintCode()

        if frame.f_code.co_name == "main" and event == "return" and self.profmode:
            self.SdbgPrintProfile()

        return self.SdbgTrace
