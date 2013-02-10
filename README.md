logwrap
=======

Monitor log files for patterns and then execute actions.

## Overview

LogWrap is a utility that can monitor log files in real-time for
patterns, generate events when those patterns are matched, and then
process events in a variety of manners using event handlers to do the
processing.  The base package includes event handlers to print, send
email messages, and fire SNMP traps.  In addition, simple event
suppression can be performed based on count and frequency of event
arrival.  Detailed tutorials exist on how to use the suppression-based
event handlers, as well as how to create your own custom event
handlers (see the Usage section below for links).

The following Python packages are part of the logwrap proper (click on
the package name for the pydoc):

[com.kazmier.utils]  
Contains the `TailFollow` package which is used to follow output
that is appended to a file (similar to a `tail -f` command).  In
addition, it will track the file as its rotated by log rotation
scripts.  Tracking is the ability to close the old file descriptor
after a new file has been created with the original name in the
filesystem.

[com.kazmier.event]  
Simple event framework that consists of event generators, a
dispatcher, and event handlers that process the events.  The framework
can be used for other applications as its not dependent on any other
logwrap package.

[com.kazmier.logwrap]  
The package that contains core functionality for the wrapping of log
files.  It includes the LogEncapsulator class which enables a user to
specify one or more files to monitor with a specific set of Rules.  A
Rule defines the pattern to be matched, as well as the EventHandlers
that should process events matching the Rule.  Also included in the
package are some simple event suppression handlers (based on count and
frequency), a `MailEventHander`, and an `SnmpTrapEventHandler`. Finally,
a `Builder` is included that can generate `LogEncapsulators` based on an
XML configuration file.

[com.kazmier.utils]: http://www.kazmier.com/computer/logwrap/pydocs/utils/
[com.kazmier.event]: http://www.kazmier.com/computer/logwrap/pydocs/event/
[com.kazmier.logwrap]: http://www.kazmier.com/computer/logwrap/pydocs/logwrap/

## Usage and Documentation

The logwrap package can be used directly in Python programs by
utilizing the API directly.  Example use of the API is documented in
the pydocs (start by looking at the [LogEncapsulator] documentation).
Alternatively (and much more common), the `logwrap` script can be
invoked from the command line with a single argument specifying an XML
configuration file.  For example::

```
  $ logwrap /home/kaz/syslog-logwrap.xml
```

The configuration file specifies the files, patterns within those
files to be monitored, and actions to take upon successful matches.
See the sample [configuration] file included in the distribution (it is
thoroughly documented).  If you want to run the logwrap program as a
daemon (in the background), specify the `-d` option::

```
  $ logwrap -d /home/kaz/syslog-logwrap.xml
```

For a detailed explanation on the various event suppression handlers
available in the LogWrap framework, please check out the document on
[SuppressionHandlers].  It will shed light on the how event handler
chains and suppression-based matching work alongside with the packaged
suppression-based event handlers.

In addition, there is an advanced [CustomEventHandlerTutorial] on how
to create your own custom event handler that will telnet to a host and
execute a command when a specific log message is received.  This
example provides yet another sample XML configuration file as well as
a simple python script that defines the custom event handler.  The
tutorial assumes you already have a general understanding of how
logwrap works.

[LogEncapsulator]: http://www.kazmier.com/computer/logwrap/pydocs/logwrap/LogEncapsulator.html
[configuration]: http://www.kazmier.com/computer/logwrap/logwrap.xml
[SuppressionHandlers]: http://www.kazmier.com/computer/logwrap/suppression.html
[CustomEventHandlerTutorial]: http://www.kazmier.com/computer/logwrap/custom-tutorial.html

## Installation

Installationn is simple and easy thanks to the Python distutils.
First, you need to download two Python packages into a temporary
directory:

1. [LogWrap]
2. [PySNMP] (only download if you want to fire SNMP traps)

[LogWrap]: http://www.kazmier.com/computer/logwrap/logwrap-CURRENT.tar.gz
[PySNMP]: http://www.kazmier.com/computer/logwrap/pysnmp-CURRENT.tar.gz

After downloading, you need to install each package.  Package
intallation is simple in Python.  The following procedure will work for
both packages::

```
    $ gunzip package.tar.gz
    $ tar xvf package.tar
    $ cd package
    $ sudo python setup.py install
```

Repeat the above procedure for both downloaded packages.  Feel free to
clean up and remove the tar files and/or untar directories.
Installation is now complete.

Four Python packages were installed in the system:

1. com.kazmier.utils
2. com.kazmier.event
3. com.kazmier.logwrap
4. pysnmp

In addition, a script called `logwrap` will be installed into one of
your system `bin` directories.  This is the program that users will
execute to start log monitoring.

## Change Log

v1.0  
  * Fixed a bug that would prevent the MailHandler from permitting other
    Handlers in the EventChain to fire.  

v0.7  
  * Fixed some rounding issues.

v0.6  
  * This version wraps up all of the 0.5.x changes into a new release
    with the added enhancement that variable interpolation occurs for
    any text node or attribute value in the XML config.

  * The EventDispatcher can now accept an event handler that will be
    used if an error occurs during the processing of other events.
    When an error occurs in the dispatching of events, a new event is
    generated and passed to this error handler.  The new event passes
    a 2-item tuple as the event.data object.  The first item is the
    exception, and the second item is the original event that caused
    the exception.

  * Users can also specify one or more handlers via the XML
    configuration file.  The handlers specified in the config file
    automatically wrapped by the new ErrorHandlerAdapter which permits
    users to use existing logwrap handlers (those that expect a
    LogMatch object as the event.data object).  The
    ErrorHandlerAdapter converts the event.data tuple (containing the
    exception and original event) into a LogMatch object.

v0.5.3  
  * The XML configuration file now supports interpolation of environment
    variables.  Any text in the form of '${ENVIRONMENT_VARIABLE}' is now
    replaced with the value of ENVIRORNMENT_VARIABLE.

v0.5.2  
  * TailFollow now monitors file size when tracking files.  If the file
    size is smaller, then it is assumed the file was replaced and that
    we now need to reread the file to catch up on events we missed.

  * Wrote a quick little script called 're-profile' that can be used
    to profile the speed of regular expressions.  I wrote this real 
    quick due to the lack of speed I was getting with logwrap when 
    using this regular expression: ``.+? .+? .+? (.+?) .+? (Configured .*)``
    That regexp takes approximately one second to parse a single line!
    With this little script I was able to profile the speed of several
    regexps to determine the optimal solution.

v0.5.1  
  * Added the ``-d`` flag to the logwrap program to enable daemon mode.


