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
The Builder module contains functions to convert an XML configuration
file into a set of objects that can be used in the event framework.
"""

from exceptions import Exception
from string import join
from sys import modules, path
from os import environ

from com.kazmier.event.Event import *
from com.kazmier.logwrap.LogEncapsulator import *

class BuilderError(Exception):
    """Custom exception used to report an error when converting an XML
    file to actual objects.  The exception contains the relevant node
    if applicable.
    """

    def __init__(self, value, node=None):
        """Constructor that specifies the error message, and
        optionally the node that caused the error.
        """

        self.node = node
        self.value = value

    def __str__(self):
        """Returns a string representation of the error."""
        
        text = self.value

        if self.node:
            text += '\n\n[Relevant part of logfile]\n' + self.node.toxml()

        return text

# ---- General XML functions -----------------------------------------

def interpolate_text(text, dictionary):
    """Replace occurances of ``${key}`` with the value of ``dictionary[key]``.
    This can be used to interpolate text with arbitrary dictionaries such as
    the os.environ.
    """

    interpolated = text
    for key in dictionary:
        interpolated = interpolated.replace('${'+key+'}', dictionary[key])
    return interpolated

def get_text(nodelist):
    """Get the text nodes and concatenate them together.  This also
    includes CDATA sections.
    """

    text = ''
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE or \
           node.nodeType == node.CDATA_SECTION_NODE:
            text = text + str(node.data)
    return interpolate_text(text, environ).rstrip()

def get_child_elements(name, node, first=0):
    """Gets all children with the specified name.  This only works on
    single level unlike getElementsByTagName.  If the optional 'first'
    argument is true, return only the first element in the list or
    None if the list is empty.
    """
    matches = []

    for child in node.childNodes:
        if child.nodeType == child.ELEMENT_NODE and \
           child.nodeName == name:
            matches.append(child)

    if first:
        if len(matches) == 0:
            return None
        else:
            return matches[0]
    else:
        return matches        

# ---- Rule Building Functions ---------------------------------------

def parse_handler_constructor_args(node):
    """Create a kwarg map that contains all of the attributes of an
    element.  In addition to attributes, child nodes are also used
    (and override attribute elements).
    """

    kwargs = {}

    for att in node.attributes.keys():
        if not att == 'type':
            # use str() to convert unicode to regular string
            # otherwise you can't use this map as a **kwargs
            kwargs[str(att)] = interpolate_text(
                str(node.attributes[att].value),
                environ)

    for child in node.childNodes:
        if child.nodeType == child.ELEMENT_NODE:
            kwargs[str(child.nodeName)] = get_text(child.childNodes)

    return kwargs

def parse_handler(node):
    """Parse a handler object and locate the handler class so an
    instance can be instantiated with the supplied arguments.  A
    handler type can be specified in either of the following formats:
    ``class_name`` or ``package_name:class_name``.  In the first case,
    the specified class name is searched for in the global namespace.
    In the latter case, the specified package is searched for the
    class name. In both cases, as a convienence to users, the type
    name, if not found is automatically converted to a full name by
    appending 'EventHandler' to the end of the specified type.
    
    """

    type = interpolate_text(node.getAttribute('type'), environ)
    if not type:
        raise BuilderError, ('Each handler must have a type specified', node)
    type = type.split(':', 1)

    klass = None
    if len(type) == 1:
        # No package specified, search global namesapce
        klass_name = type[0]
        if not globals().has_key(klass_name):
            klass_name = type[0] + 'EventHandler'
            if not globals().has_key(klass_name):
                raise BuilderError, 'Handler could not be loaded: ' + type[0]
        klass = globals()[klass_name]

    else:
        # Search the package namespace for the handler class
        package_name, klass_name = type
        __import__(package_name)
        if not hasattr(modules[package_name], klass_name):
            klass_name = type[1] + 'EventHandler'
            if not hasattr(modules[package_name], klass_name):
                raise BuilderError, 'Handler could not be loaded: ' + \
                      join(type, ':')
        klass = getattr(modules[package_name], klass_name)

    kwargs = parse_handler_constructor_args(node)
    return apply(klass, (), kwargs)
    

def build_error_handler(node):
    """Scan the node for one or more handlers.  If there is only one
    handler, then that handler is simply returned.  However, if there
    are more than one handlers, they are automatically chained
    together using a ChainEventHandler.
    """

    handlers = []

    for child in get_child_elements('errorHandler', node):
        handlers.append(parse_handler(child))

    if len(handlers) == 1:
        return handlers[0]
    elif len(handlers) > 1:
        return apply(ChainEventHandler, handlers)
    else:
        return None

def build_handler(node):
    """Scan the node for one or more handlers.  If there is only one
    handler, then that handler is simply returned.  However, if there
    are more than one handlers, they are automatically chained
    together using a ChainEventHandler.
    """

    handlers = []

    for child in get_child_elements('handler', node):
        handlers.append(parse_handler(child))

    if len(handlers) == 1:
        return handlers[0]
    elif len(handlers) > 1:
        return apply(ChainEventHandler, handlers)
    else:
        raise BuilderError, ('You must have at least one handler', node)

def parse_rule(node):
    """Parse a Rule and verify it specifies a regular expression."""

    regexp_node = get_child_elements('regexp', node, first=1)
    if regexp_node == None:
        raise BuilderError, ('Each rule must have a regexp element', node)
    regexp = get_text(regexp_node.childNodes)

    quickness = 0
    quick = interpolate_text(node.getAttribute('quick'), environ)
    if quick:
        quickness = int(quick)
    
    return Rule(regexp, build_handler(node), quickness)

def build_rules(node):
    """Parse all of Rules that are part of this node.  It also ensures
    that at least one rule exists.
    """

    rules = []

    for child in get_child_elements('rule', node):
        rules.append(parse_rule(child))

    if len(rules) == 0:
        raise BuilderError, ('You must configure at least one rule', node)
    
    return rules

# ---- LogEncapsulator Building Functions ----------------------------

def parse_logFiles(node):
    """Scan all of the logFile tags and determine if they should be
    tracked.
    """
    
    files = []

    for child in get_child_elements('logFile', node):
        filename = interpolate_text(child.getAttribute('file'), environ)
        if not filename:
            raise BuilderError, ('Each logFile must have a file attribute',
                                 child)
        tracking = 1
        track = interpolate_text(child.getAttribute('track'), environ)
        if track:
            tracking = int(track)

        files.append((filename, tracking))

    return files

def parse_logEncapsulator(node):
    """Scan a LogEncapsulator and instantiate one that can be returned
    to the caller.
    """

    name = interpolate_text(node.getAttribute('name'), environ)
    if not name:
        raise BuilderError, ('Each encapsulator requires a name attribute',
                             node)

    files = parse_logFiles(node)
    if len(files) == 0:
        raise BuilderError, ('Each encapsulator requires at least one logFile',
                             node)

    encapsulator = LogEncapsulator(name)
    for (filename, tracking) in files:
        encapsulator.watch_file(filename, tracking)
    for rule in build_rules(node):
        encapsulator.add_rule(rule)

    return encapsulator

def parse_configuration(root):
    """Parses an XML document representing the configuration of the
    logwrap utility.  The document is parsed and two items are
    returned: the error handler used to process errors and a list of
    encapsulators for the event framework.
    """
    
    encapsulators = []

    config = get_child_elements('logWrap', root, first=1)
    if config == None:
        raise BuilderError, 'You must have an outer logWrap element'

    for node in get_child_elements('handlerDirectory', config):
        dir = interpolate_text(node.getAttribute('dir'), environ)
        if not dir:
            raise BuilderError, 'handlerDirectory requires a dir attribute'
        path.append(str(dir))

    error_handler = build_error_handler(config)
    if error_handler:
        error_handler = ErrorHandlerAdapter(error_handler)
    
    for node in get_child_elements('logEncapsulator', config):
        encapsulators.append(parse_logEncapsulator(node))

    if len(encapsulators) == 0:
        raise BuilderError, 'You must configure at least one log encapsulator'

    return error_handler, encapsulators
