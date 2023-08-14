### Description

This content pack provides a simple debugger for debugging custom python automations in XSOAR.  You can visually trace code execution, set breakpoints, step through the code, display local variables, and profile execution times of python functions.

### Overview

The **SimpleDebugger** is a python class definition appended to **CommonServerUserPython** and dynamically included in every automation by the XSOAR automation execution environment.

There are two static lists in the debugger to minimize code being traced.  The exclusion list contains python runtime functions as well as common functions such as ```json.dumps()``` and ```json.loads()```.  The second list, the silent list, is used to avoid tracing common demisto class functions such as ```demisto.executeCommand()```,  ```demisto.args()```, ```demisto.incident()```, ```demisto.incidents()```, and ```demisto.context()```.  Functions on the silent list appear in the code trace, their call and return are logged, and they are included in the performance profile; they are not traced line by line. The debugger allows additional functions to be added to the exclude and silent lists.

When an exception occurs, the function's absolute and relative line numbers are printed along with local variables. The relative line number allows identification of the line causing the exception.

### Getting Started

To debug an automation:

- Append the **SimpleDebugger** automation to your **CommonServerUserPython** automation
- Edit your automation to enable the debugger (see example automation debugging template below)
- Create a new incident of type **SimpleDebugger**
- In the *War Room* tab of the incident, execute your automation from the XSOAR command line
- In the *Simple Debugger* tab, debug your automation

### Debugger Commands

The following debugging commands are entered by editing the *Simple Debugger Cmd* field during a debug session.

- stop
- step
- continue
- print {func1}, {func2.var1}, {func3.var1}, ...
- break {func1}, {line_number1}, {func2}, {func3}, {line_number2}, ...
- nolog
- log

#### stop
The *stop* command halts debugging and exits the automation
#### step
Once a breakpoint is reached, the *step* command is used to step through the automation one line at a time. The *continue* command clears the single step mode
#### continue
The *continue* command continues execution after a breakpoint or if using *step*
#### print 
The *print* command is used to print local variables, either all the local variables in a function when the function name is by itself, or specified local variables using dot notation **{function name}.{variable name}**
#### break  
The *break* command sets a breakpoint by function name when calling a function or by line number.  Break points are set on the automation's absolute line number, not the function's relative line number. In an example line **11485:[9] main()**,  11485 is the absolute line number and 9 is the function relative line number. When a breakpoint is reached, the functions local variables are printed
#### nolog
The *nolog* command is used to disable logging in large or long running automations with substantial looping to eliminate field updates messages being sent to the *War Room*
#### log
The *log* command is used to re-enable logging once an area of interest in the code is reached

### Debugger Inputs

Debugger inputs are commands used to configure the debugger's operating mode prior to executing your automation.  These commands are read in once at the initiation of a debug session. The *Simple Debugger Input* field is edited prior to launching the automation in the *War Room*.

- quiet
- profile
- print {func1}, {func2.var1}, {func3.var1}, ...
- break {func1}, {line_number1}, {func2}, {func3}, {line_number2}, ...
- nolog
- exclude {func1}, {func2}, ...
- silent {func1}, {func2}, ...

#### quiet
The *quiet* command places the debugger in a the quiet mode where a line of code is displayed only the first time in the *Simple Debugger Code* field.  Dynamic tracing of the currently executing line is disabled. This minimizes field changes echoed to the *War Room* speeding execution and preventing consumption of excessive browser memory but senables visibility of the code for setting breakpoints 
#### profile
The *profile* command provides execution time profile of python functions with the number of times the function is called and the average execution duration. The profile results are displayed in the *Simple Debugger Data* field when ```main()``` returns. It is best used with the *quiet* and *nolog* mode to minimize performance impacts during profiling
#### print  
The *print* command prints out the local variables specified each time the function returns. It supports the same syntax as in Debugger Commands 
#### break
The *break* command is the same as in Debugger Commands
#### nolog
The *nolog* command is the same as in Debugger Commands
#### exclude
The *exclude* command allows adding a comma seperated list of functions to the *exclude list* to prevent them from being traced in the debugger 
#### silent
The *silent* command allows adding a comma seperated list of functions to the *silent list* to skip tracing them line by line

### Caveats

- Breakpoints have a 5 minute timeout to avoid automations being left in a running state while deugging
- Automations with significant looping should be run in *quiet* mode. Otherwise, an entry in the *War Room* is created for each line executed, slowing execution and consuming browser memory. *nolog* mode is used for the same reason
- A new debugging incident should be created after a long debugging session to keep the incident small and not slow the debugging session
- Always delete a debugging incident when done since they can grow quiet large and should be removed from the XSOAR database
- Run the automation first in *quiet* mode to establish line numbers and functions in use and then configure the breakpoints in the *Debugger Inputs*. Once one breakpoint is hit, additional breakpoints can be added
- Line numbers are not reflective of line numbers in the XSOAR IDE because of how automations are run by XSOAR.  To compensate, relative line numbers are included in the debugger code trace. For example, in the line trace **11485:[9] main()**  refers to the 9th line of main(). ```def main():``` is line 0
- Actual code for each line is not currently available
- If your automation needs specific incident fields and context for testing, tools like **UnitTestLoadFields** and **UnitTestLoadContext** in the **Content Testing** content pack from the Marketplace can be used to populate the debugging incident

### Automation Debugging Template

```
sdebug = SimpleDebugger()

def main():
    try:
        #
        # Code here
        #
    except Exception as ex:
        sdebug.SdbgTraceOff()
        demisto.error(traceback.format_exc())
        return_error(f'MyAutomation: Failed to execute. Error: {str(ex)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    sdebug.SdbgTraceOn()
    main()
    sdebug.SdbgTraceOff()
```

### Objects Included in the Content Pack

#### Incident Types
- **SimpleDebugger**

#### Incident Layouts
- **SimpleDebugger**

#### Incident Fields

- **simpledebuggercmd**
- **simpledebuggerinput**
- **simpledebuggeroutput**
- **simpledebuggercode**
- **simpledebuggerdata**

### Automations

- **SimpleDebugger**

#### SimpleDebugger
This automation provides the *SimpleDebugger* class and is appended to your **CommonServerUserPython**. It is not executed directly as an automation.

##### Inputs

None

##### Outputs

None

