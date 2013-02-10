#!/usr/bin/python
# Copyright (c) 2003, Pete Kazmier
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    - Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#
#    - Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials provided
#      with the distribution.
#
#    - Neither the name of the 'Kazmier' nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
"""
This module provides various classes that enable one to monitor log
files using the event framework included in this package.  There are
several classes that are part of this module, each of which are fully
documented.  A brief overview of the entire module is provided in
subsequent paragraphs.

The primary class that users interact with is the LogEncapsulator.
The LogEncapsulator implements the EventGenerator interface (its a
source of Events).  Each LogEncapsulator is configured with one or
more files to monitor using a single set of Rules.  A Rule is used to
determine if a match has occurred when monitoring, and when that Event
does occur, the Rule specifies the EventHandler used to process the
Event (see the Event module for details on the event framework).

The EventHandler used to process a LogEncapsulator generated Event can
expect that the Event's data property contains a LogMatch object.  The
LogMatch object simply encapsulates the line from the log file that
triggered the match, as well as the match object from the re package.
This package includes various EventHandlers that can be used as part
of a Rule definition.

Sample use of this module follows::

  #!/usr/bin/python
  
  from time import sleep
  from com.kazmier.event.Event import EventDispatcher
  from com.kazmier.event.Event import ChainEventHandler
  from com.kazmier.event.Event import PrintEventHandler
  from com.kazmier.logwrap.LogEncapsulator import Rule
  from com.kazmier.logwrap.LogEncapsulator import LogEncapsulator
  from com.kazmier.logwrap.LogEncapsulator import WaitToCountEventHandler
  
  dispatcher = EventDispatcher()
  try:
      encapsulator = LogEncapsulator("Test Encapsulator")
      encapsulator.watch_file("/var/log/syslog")
      encapsulator.watch_file("/var/log/maillog")
      encapsulator.add_rule(Rule("some pattern", PrintEventHandler()))
      encapsulator.add_rule(Rule("another", ChainEventHandler(
                                              WaitToCountEventHandler(),
                                              PrintEventHandler())))
      dispatcher.error_handler(ErrorHandlerAdapter(PrintEventHandler()))
      dispatcher.add_event_generator(encapsulator)
      dispatcher.start()
      while 1:
          sleep(1)
  
  except Exception, e:
      dispatcher.stop()
      print e


If you do not want to use the API directly, there is a tool called
logwrap that will parse an XML file and generate all of the
appropriate encapsulators and rules automatically.
"""

from exceptions import Exception
from re import compile, search
from smtplib import SMTP
from string import join
from sys import stderr
from threading import Thread
from time import sleep, time
from types import StringType

from pysnmp import role, v2c, asn1
from com.kazmier.event.Event import Event, EventHandler, EventGenerator
from com.kazmier.utils.TailFollow import TailFollow

class Rule(object):
    """A rule is comprised of a pattern and an event handler.  The
    event handler is used to process events that are generated when
    the pattern is matched in a log file.  In addition, a rule can
    also be 'quick', which indicates that upon a match, all further
    processing should stop.  By default, a message from a log file
    can match multiple rules.
    """

    def __init__(self, regexp, handler, quick=0):
        """Constructor that specifies the regular expression used to
        match lines, the event handler used to process events, and an
        optional flag indicating the quickness of the rule.
        """

        self.regexp = compile(regexp)
        self.handler = handler
        self.quick = quick

    def __str__(self):
        """Returns a string representation of a rule."""

        return "[" + str(self.quick) + "] " + \
               self.regexp.pattern + " --> " + \
               str(self.handler)


class LogMatch(object):
    """When an event is generated, indicating a log match, the event
    contains a LogMatch object that contains the line that caused the
    event to be generated, as well as the 're.match' object so that
    individual components of the matched can be fetched.
    """

    def __init__(self, line, match):
        """Constructor that specifies the line that caused a match to
        occur, as well as the match object returned by the 're'
        module.
        """

        self.line = line
        self.match = match

    def __str__(self):
        """Returns a string representation of the LogMatch."""

        return str(self.match.groups()) + ' ' + self.line


class LogEncapsulator(EventGenerator):
    """Wraps one or more log files and generates events based on
    regular expressions that match log entries.  In addition, if the
    log file(s) are moved or rotated, the original file(s) are closed,
    and the new file(s) are re-opened (see TailFollow for more
    details).

    When the LogEncapsulator creates an Event, the event data is an
    instance of LogMatch which contains the original log line that
    caused the event, as well as a match object from the regular
    expression.  This match object can then be used by the
    EventHandler when processing the Event.

    The LogEncapsulator is designed to be used in the Event framework
    that accompanies this module.  Specifically, the encapsulator is
    an instance of an EventGenerator and must be added to an
    EventDispatcher to process events that are generated.
    """
    
    def __init__(self, name):
        """Constructor that specifies the name of the encapsulator."""

        self.name = name
        self.rules = []
        self._watched_files = []

    def __str__(self):
        """Returns the name of the encapsulator."""

        return self.name

    def watch_file(self, filename, track=1):
        """Watch the specified file for new data that may or may not
        trigger an event based on the configured rules.  An optional
        parameter called 'track' can be used to indicate if the file
        should be tracked in the event it is rotated (by default).
        """

        self._watched_files.append(TailFollow(filename, track))

    def add_rule(self, rule):
        """Add the rule to the current set of rules that will be used
        to process new data from the various files being watched.
        """
        
        self.rules.append(rule)

    def stop(self):
        """Stop the encapsulator and cleanly shutdown all resources
        currently in use such as the files that are being tracked via
        TailFollow.
        """
        
        for watched_file in self._watched_files:
            watched_file.close()

    def get_events(self):
        """Gets all pending events that have occurred since the last
        time this method was invoked.  An event is generated when a
        log entry matches one of the rules associated with this
        encapsulator.
        """

        events = []

        for watched_file in self._watched_files:
            for line in watched_file:
                self._do_rule_processing(line, events)

        return events

    def _do_rule_processing(self, line, events):
        """Scan all of the rules for a match and generate an event
        upon a successful match.  Add the event to the collecting
        parameter called 'events'.
        """

        for rule in self.rules:
            match = rule.regexp.search(line)
            if match:
                events.append(Event(self, rule.handler, LogMatch(line, match)))
                if rule.quick:
                    break


class WaitToCountEventHandler(EventHandler):
    """An event handler that only succeeds when a particular count
    threshold has been exceeded for the same matched log message.
    This event handler is designed to be used in a ChainEventHandler
    as it doesn't provide any functionality by itself.  
    """

    def __init__(self, threshold=3, reset=1, match_on=(0,)):
        """Constructor that specifies the threshold (or count) that
        must be exceeded before the event handler returns success
        (which enables the chain to proceed).  An optional boolean
        argument called 'reset' can be used to indicate that the
        handler should reset its count upon success (thereby resetting
        the trigger), otherwise, a message is generated for each
        subsequent event.  Finally, the 'match_on' optional parameter
        specifies a tuple of fields that are used to match a message
        with a count.  This enables users to key off of a part of the
        message when incrementing a count.
        """

        self._count = {}
        self.reset = int(reset)
        self.threshold = int(threshold)
        self.match_on = match_on
        if isinstance(match_on, StringType):
            self.match_on = [int(x.strip()) for x in match_on.split(',') if x]

    def process_event(self, event):
        """Process an event and check if it has exceeded the current
        threshold.  If the threshold has been exceeded, return a 1 to
        indicate success, otherwise return 0 which is used to stop
        event processing in the chain.
        """

        key = apply(event.data.match.group, self.match_on)
        
        self._increment_count(key)

        if self._count[key] >= self.threshold:
            if self.reset:
                del self._count[key]
            return 1

        return 0

    def _increment_count(self, key):
        """Increment the count for a specific key."""

        if not self._count.has_key(key):
            self._count[key] = 0

        self._count[key] += 1
        
# For backwards compatibility when there was only one count handler 
CountEventHandler = WaitToCountEventHandler


class IntervalCountEventHandler(EventHandler):
    """An event handler that succeeds upon receipt of the first
    matched log message and thereafter only when the interval has been
    exceeded.  Note, this is different from the WaitToCount event
    handler which succeeds only after the threshold has been exceeded.
    This event handler is designed to be used in a ChainEventHandler
    as it doesn't provide any functionality by itself.
    """

    def __init__(self, threshold=3, match_on=(0,)):
        """Constructor that specifies the threshold (or interval) that
        must intervene between matched log messages before success is
        returned (which enables the chain to proceed).  The 'match_on'
        optional parameter specifies a tuple of fields that are used
        to match a message with a count.  This enables users to key
        off of a part of the message when incrementing a count.
        """

        self._count = {}
        self.threshold = int(threshold)
        self.match_on = match_on
        if isinstance(match_on, StringType):
            self.match_on = [int(x.strip()) for x in match_on.split(',') if x]

    def process_event(self, event):
        """Process an event and check if it has exceeded the current
        threshold.  If the threshold has been exceeded, return a 1 to
        indicate success, otherwise return 0 which is used to stop
        event processing in the chain.  Also return 1 upon receipt of
        the first event.
        """

        key = apply(event.data.match.group, self.match_on)
        
        self._increment_count(key)

        if self._count[key] == 1:
            return 1
        elif self._count[key] == self.threshold:
            del self._count[key]

        return 0

    def _increment_count(self, key):
        """Increment the count for a specific key."""

        if not self._count.has_key(key):
            self._count[key] = 0

        self._count[key] += 1
        

class WaitToFrequencyEventHandler(EventHandler):
    """An event handler that only succeeds when a particular frequency
    threshold has been exceeded for the same matched log message.
    This event handler is designed to be used in a ChainEventHandler
    as it doesn't provide any functionality by itself.
    """
    
    def __init__(self, threshold=3, interval=60, reset=1, match_on=(0,)):
        """Constructor that specifies the threshold (or count) that
        must be exceeded within the specified interval before the
        event handler returns success (which enables the chain to
        proceed).  An optional boolean argument called 'reset' can be
        used to indicate that the handler should reset its count upon
        success (thereby resetting the trigger), otherwise the
        previous events are taken into account in subsequent
        calculations.  Finally, the 'match_on' optional parameter
        specifies a tuple of fields that are used to match a message
        with a count.  This enables users to key off of a part of the
        message when incrementing a count.
        """

        self._event_times = {}
        self.interval = int(interval)
        self.reset = int(reset)
        self.threshold = int(threshold)
        self.match_on = match_on        
        if isinstance(match_on, StringType):
            self.match_on = [int(x.strip()) for x in match_on.split(',') if x]

    def process_event(self, event):
        """Process an event and check if it has exceeded the current
        threshold.  If the threshold has been exceeded, return a 1 to
        indicate success, otherwise return 0 which is used to stop
        event processing in the chain.
        """

        key = apply(event.data.match.group, self.match_on)

        self._append_event_time(key, event.time)

        # Only keep the 'threshold' amount of alarm history

        if len(self._event_times[key]) > self.threshold:
            del self._event_times[key][0]

        # If we actually have 'threshold' alarms, then we need
        # to make sure that the frequency of these alarms has
        # not exceeded the interval.

        if len(self._event_times[key]) == self.threshold:
            if round(event.time - self._event_times[key][0]) < self.interval:
                if self.reset:
                    del self._event_times[key]
                return 1

        return 0

    def _append_event_time(self, key, timestamp):
        if not self._event_times.has_key(key):
            self._event_times[key] = []

        self._event_times[key].append(timestamp)

# For backwards compatibility when there was only one frequency handler 
FrequencyEventHandler = WaitToFrequencyEventHandler


class LimitToFrequencyEventHandler(EventHandler):
    """An event handler that only succeeds when a particular frequency
    threshold has not been exceeded for the same matched log message.
    This event handler is designed to be used in a ChainEventHandler
    as it doesn't provide any functionality by itself.
    """

    def __init__(self, threshold=3, interval=60, reset=1, match_on=(0,)):
        """Constructor that specifies the threshold (or count) that
        must not be exceeded within the specified interval before the
        event handler returns success (which enables the chain to
        proceed).  An optional boolean argument called 'reset' can be
        used to indicate that the handler should reset its count upon
        success (thereby resetting the trigger), otherwise the
        previous events are taken into account in subsequent
        calculations.  Finally, the 'match_on' optional parameter
        specifies a tuple of fields that are used to match a message
        with a count.  This enables users to key off of a part of the
        message when incrementing a count.
        """

        self._event_times = {}
        self.interval = int(interval)
        self.reset = int(reset)
        self.threshold = int(threshold)
        self.match_on = match_on        
        if isinstance(match_on, StringType):
            self.match_on = [int(x.strip()) for x in match_on.split(',') if x]

    def process_event(self, event):
        """Process an event and check if it has exceeded the current
        threshold.  If the threshold has not been exceeded, return a 1
        to indicate success, otherwise return 0 which is used to stop
        event processing in the chain.
        """

        key = apply(event.data.match.group, self.match_on)

        self._append_event_time(key, event.time)

        if len(self._event_times[key]) == 1:
            return 1

        if round(event.time - self._event_times[key][0]) < self.interval:
            if len(self._event_times[key]) > self.threshold:
                del self._event_times[key][-1:]
                return 0
        else:
            if self.reset:
                del self._event_times[key][0:-1]
            else:
                del self._event_times[key][0]

        return 1

    def _append_event_time(self, key, timestamp):
        if not self._event_times.has_key(key):
            self._event_times[key] = []

        self._event_times[key].append(timestamp)


class ErrorHandlerAdapter(EventHandler):
    """ErrorHandlerAdapter adapts the Event generated by the
    EventProcessor for errored events such that the data field of the
    Event object contains a LogMatch object.  This enables users to
    use their existing library of event handlers written that expect
    LogMatch objects to be present.  For example, this adapter class
    enables users to use the MainEventHandler and SnmpEventHandlers
    defined in this class.

    The adapter works by introspecting the data object contained
    within the original event which is a tuple that contains the
    exception as well as the original event that caused the error.
    These two values are placed into a Match object in fields 1 and 2
    respectively.  Thus, handlers can use match.group(1) to obtain the
    exception, and match.group(2) to obtain the original event.
    """

    pattern = compile('Processing Error: (.+?) Event: (.+)')

    def __init__(self, handler):
        """Constructor that specifies an event handler wishing to
        receive an adpated event that contains a LogMatch object in
        the Event's data field.
        """

        self.event_handler = handler

    def process_event(self, event):
        """Adapts the event to a format expected by logwrap event handlers."""
        
        message = 'Processing Error: ' + str(event.data[0]) + ' '\
                  'Event: ' + str(event.data[1])

        match = ErrorHandlerAdapter.pattern.search(message)
        event.data = LogMatch(message, match)

        self.event_handler.process_event(event)

class MailEventHandler(EventHandler):
    """MailEventHandler sends an email message that can optionally
    contain parts of the log message that generated the event.  The
    subject and body strings are examined for any sequence of ``\\n``
    where ``n`` is a digit from 0 to 99 that represents the
    appropriate group of the match object that was included as part of
    the LogMatch Event data.
    """

    def __init__(self, fromaddr, toaddrs, subject='', body='',
                 smtphost='localhost'):
        """Constructor that specifies the sender, a list of
        recipients, a subject, and a body.  The subject and body are
        interpolated for special characters that should be replaced by
        parts of the event.
        """

        if isinstance(toaddrs, StringType):
            self.toaddrs = [x.strip() for x in toaddrs.split(',') if x]
        else:
            self.toaddrs = toaddrs
            
        self.fromaddr = fromaddr
        self.subject = subject
        self.body = body
        self.smtphost = smtphost

    def process_event(self, event):
        """Sends an email in response to the Event."""
        message = 'From: ' + self.fromaddr + \
                  '\nTo: ' + join(self.toaddrs, ', ') + \
                  '\nSubject: ' + event.data.match.expand(self.subject) + \
                  '\n\n' + \
                  event.data.match.expand(self.body) + '\n' 

        try:
            server = SMTP(self.smtphost)
            server.sendmail(self.fromaddr, self.toaddrs, message)
            server.quit()

        except Exception, e:
            print >> stderr, "Could not send mail:", e

        return 1

class SnmpTrapEventHandler(EventHandler):
    """SnmpTrapEventHandler sends an SNMP trap that can optionally
    contain parts of the log message that generated the event as
    varbinds of the trap.  Each varbind message body can contain
    ``\\n`` where ``n`` is a digit from 0 to 99 that represents the
    appropriate group of the match object that was included as part of
    the LogMatch Event data.
    """

    # Canonical objects. No need to dispose of them and then
    # only to re-create them later.
    INTEGER = asn1.INTEGER()
    UNSIGNED32 = asn1.UNSIGNED32()
    TIMETICKS = asn1.TIMETICKS()
    IPADDRESS = asn1.IPADDRESS()
    OBJECTID = asn1.OBJECTID()
    OCTETSTRING = asn1.OCTETSTRING()
    COUNTER64 = asn1.COUNTER64()

    sysUpTime = OBJECTID.encode('1.3.6.1.2.1.1.3.0')
    sysTrapOID = OBJECTID.encode('1.3.6.1.6.3.1.1.4.1.0')

    def __init__(self, hosts, community, trapoid, varbinds=()):
        """Constructor that specifies the a list of hosts, a community
        string to use for all of the hosts, the OID of the trap, as
        well as a sequence of varbinds.  Each varbind sequence is a
        tuple that contains the OID, type, and value (all of which are
        specified as strings).  For example::

          trap = SnmpTrapEventHandler( \\
                   ("host1", "host2"),
                   "public",
                   "1.3.6.1.4.1.8233.111.1",
                   (("1.3.6.1.4.1.8233.200.1", "OCTETSTRING", "Error"),
                    ("1.3.6.1.4.1.8233.200.2", "INTEGER", 100),
                    ("1.3.6.1.4.1.8233.200.3", "INTEGER", "\\2")))
        
        As an alternative, all of the arguments may be specified as
        strings.  In which case, the following is the expected
        format::

          trap = SnmpTrapEventHandler( \\
                   "host1, host2",
                   "public",
                   "1.3.6.1.4.1.8233.111.1",
                   "1.3.6.1.4.1.8233.200.1: OCTETSTRING: Error
                    1.3.6.1.4.1.8233.200.2: INTEGER: 100
                    1.3.6.1.4.1.8233.200.3: INTEGER: \\2")

        The string formats are designed for external programmatic
        applications (such as an XML rule builder, or GUI front-end.
        """

        if isinstance(hosts, StringType):
            hosts = [x.strip() for x in hosts.split(',') if x]

        self.hosts = [ role.manager((x, 162)) for x in hosts ]
        self.community = community
        self.trapoid = SnmpTrapEventHandler.OBJECTID.encode(trapoid)

        if isinstance(varbinds, StringType):
            varbinds = [x.strip().split(':') 
                        for x in varbinds.split('\n') if x]

        for oid, type, value in varbinds:
            if not hasattr(asn1, type):
                raise TypeError, "SNMP type does not exist: " + type

        self.varbinds = [(SnmpTrapEventHandler.OBJECTID.encode(o), t, v)
                         for o, t, v in varbinds] 

    def process_event(self, event):
        """Sends an SNMP Trap in response to the Event."""

        trap = v2c.TRAP()
        self._encoded_oids = []
        self._encoded_vals = []

        # Since this is a v2 trap, we must include sysUpTime as well
        # as sysTrapOID to indicate what the OID of this trap.
        self._add_varbind(SnmpTrapEventHandler.sysUpTime,
                          SnmpTrapEventHandler.TIMETICKS.encode(int(time())))
        self._add_varbind(SnmpTrapEventHandler.sysTrapOID,
                          self.trapoid)

        # We do late encoding of the value data because it may contain
        # positional parameters that need to be expanded on a per
        # event basis.  
        for oid, type, value in self.varbinds:
            self._add_varbind(oid, self._encode_value(type, 
                                                      value, 
                                                      event.data.match))
        # Encode the trap and send it to all hosts.
        encoded_trap = trap.encode(encoded_oids=self._encoded_oids,
                                   encoded_vals=self._encoded_vals)
        for host in self.hosts:
            host.send(encoded_trap)

        return 1

    def _encode_value(self, type, value, match):
        """Encode each value using the specified type, but first do
        any positional parameter expansion if the value is a string,
        and then convert to the native type.
        """
        
        if type == 'INTEGER':
            if isinstance(value, StringType):
                value = int(match.expand(value))
        elif type == 'UNSIGNED32':
            if isinstance(value, StringType):
                value = int(match.expand(value))
        elif type == 'TIMETICKS':
            if isinstance(value, StringType):
                value = int(match.expand(value))
        elif type == 'IPADDRESS':
            if isinstance(value, StringType):
                value = match.expand(value)
        elif type == 'OBJECTID':
            if isinstance(value, StringType):
                value = match.expand(value)
        elif type == 'OCTETSTRING':
            if isinstance(value, StringType):
                value = match.expand(value)
        elif type == 'COUNTER64':
            if isinstance(value, StringType):
                value = int(match.expand(value))

        return eval('SnmpTrapEventHandler.' + type).encode(value)

    def _add_varbind(self, oid, value):
        """Add the varbind to the appropriate arrays.  Oddly enough, the
        API for pysnmp (v2, apparently v3 is going to be better) is a
        bit awkward requiring the maintenance of two separate lists
        containing oid and values.
        """
        
        self._encoded_oids.append(oid)
        self._encoded_vals.append(value)
