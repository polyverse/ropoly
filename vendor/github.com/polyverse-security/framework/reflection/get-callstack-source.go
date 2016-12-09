package reflection

import (
	"fmt"
	"runtime"
)

/*****************************************************************************************
GetCallStackSource: Retrieves the source location on the callstack where a key entry-point call was made.

For instance, if you want to know from where a call to the logger was made (function name, file name and
line number), or where a call to a timer was made or where a call to a finalizer was made from, this
function gives you that information.

All it needs is a function that can identify the entry-point you are looking for, and it will
return you a string that describes the caller to that entry-point.

Let us say your entrypoint was called "Log" and you wanted to know from where on the callstack,
the last call to Log was made. All you do is, define a boolean:

func isLogEntryPoint(funcname string) bool {
    if strings.Contains(funcname, "package.Log") {
    	return true
    }
    return false
}

then call:

source := GetCallstackSource(isLogEntryPoint)

source will now contain a description of from where the call to Log was made.

This is used heavily in our logging and timer libraries
to know where timers were started from or stopped, as well as from what line a particular
log entry was made from.

 *****************************************************************************************/
func GetCallstackSource(isEntryFunc func(string) bool) string {
	var callers []uintptr = make([]uintptr, 10, 10)
	numcallers := runtime.Callers(3, callers) //0 is Callers, 1 is us (this specific hook)
	if numcallers > 0 {
		//Find first stackframe containing the "log call"
		for _, pc := range callers {
			f := runtime.FuncForPC(pc - 1)
			if !isEntryFunc(f.Name()) {
				//Then we want this guy's caller!
				filename, line := f.FileLine(pc - 1)
				return fmt.Sprintf("%s(%s:%d)", f.Name(), filename, line)
			}
		}
	}
	return ""
}

/**
GetCallstackFormatted - returns the full callstack above the
function identified as Entry function.
*/
func GetCallstackFormatted() string {
	buf := make([]byte, 1<<16)
	count := runtime.Stack(buf, false)
	return fmt.Sprintf("%s", buf[0:count])
}
