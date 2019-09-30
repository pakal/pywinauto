# GUI Application automation and testing library
# Copyright (C) 2006-2018 Mark Mc Mahon and Contributors
# https://github.com/pywinauto/pywinauto/graphs/contributors
# http://pywinauto.readthedocs.io/en/latest/credits.html
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of pywinauto nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Provides functions for iterating and finding windows/elements"""
from __future__ import unicode_literals

import locale
import os
import re
import ctypes
import six
import sys

from . import win32functions
from . import win32structures
from . import findbestmatch
from . import controls
from .backend import registry


# TODO: we should filter out invalid elements before returning

#=========================================================================
class WindowNotFoundError(Exception):

    """No window could be found"""
    pass


#=========================================================================
class WindowAmbiguousError(Exception):

    """There was more then one window that matched"""
    pass


#=========================================================================
class ElementNotFoundError(Exception):

    """No element could be found"""
    pass


#=========================================================================
class ElementAmbiguousError(Exception):

    """There was more then one element that matched"""
    pass


# =========================================================================
def print_control_identifiers(control, depth=None, filename=None, log_func=None):
    """
    Prints the 'identifiers' of a control.

    Prints identifiers for the control and for its descendants to
    a depth of **depth** (the whole subtree if **None**).

    By default, identifiers are printed to stdout. A filename may be provided to output the identifiers to,
    else a `log_func` callback accepting

    .. note:: The identifiers printed by this method have been made
           unique. So if you have 2 edit boxes, they won't both have "Edit"
           listed in their identifiers. In fact the first one can be
           referred to as "Edit", "Edit0", "Edit1" and the 2nd should be
           referred to as "Edit2".
    """

    if depth is None:
        depth = sys.maxsize

    if hasattr(control, "wrapper_object"):
        # Resolve this control
        this_ctrl = control.wrapper_object()
    else:
        # Already a wrapper object
        this_ctrl = control

        # Create a list of this control and all its descendants
    all_ctrls = [this_ctrl, ] + this_ctrl.descendants()

    # Create a list of all visible text controls
    txt_ctrls = [ctrl for ctrl in all_ctrls if ctrl.can_be_label and ctrl.is_visible() and ctrl.window_text()]

    # Build a dictionary of disambiguated list of control names
    name_ctrl_id_map = findbestmatch.UniqueDict()
    for index, ctrl in enumerate(all_ctrls):
        ctrl_names = findbestmatch.get_control_names(ctrl, all_ctrls, txt_ctrls)
        for name in ctrl_names:
            name_ctrl_id_map[name] = index

    # Swap it around so that we are mapped off the control indices
    ctrl_id_name_map = {}
    for name, index in name_ctrl_id_map.items():
        ctrl_id_name_map.setdefault(index, []).append(name)

    def print_identifiers(ctrls, current_depth=1, log_func=None):
        """Recursively print ids for ctrls and their descendants in a tree-like format"""
        if len(ctrls) == 0 or current_depth > depth:
            return
        assert log_func, log_func

        indent = (current_depth - 1) * u"   | "
        for ctrl in ctrls:
            try:
                ctrl_id = all_ctrls.index(ctrl)
            except ValueError:
                continue
            ctrl_text = ctrl.window_text()
            if ctrl_text:
                # transform multi-line text to one liner
                ctrl_text = ctrl_text.replace('\n', r'\n').replace('\r', r'\r')

            output = indent + u'\n'
            output += indent + u"{class_name} - '{text}'    {rect}\n" \
                               "".format(class_name=ctrl.friendly_class_name(),
                                         text=ctrl_text,
                                         rect=ctrl.rectangle())
            output += indent + u'{}'.format(ctrl_id_name_map[ctrl_id])

            title = ctrl_text
            class_name = ctrl.class_name()
            auto_id = None
            control_type = None
            if hasattr(ctrl.element_info, 'automation_id'):
                auto_id = ctrl.element_info.automation_id
            if hasattr(ctrl.element_info, 'control_type'):
                control_type = ctrl.element_info.control_type
                if control_type:
                    class_name = None  # no need for class_name if control_type exists
                else:
                    control_type = None  # if control_type is empty, still use class_name instead
            criteria_texts = []
            if title:
                criteria_texts.append(u'title="{}"'.format(title))
            if class_name:
                criteria_texts.append(u'class_name="{}"'.format(class_name))
            if auto_id:
                criteria_texts.append(u'auto_id="{}"'.format(auto_id))
            if control_type:
                criteria_texts.append(u'control_type="{}"'.format(control_type))
            if title or class_name or auto_id:
                output += u'\n' + indent + u'child_window(' + u', '.join(criteria_texts) + u')'

            log_func(output)

            print_identifiers(ctrl.children(), current_depth + 1, log_func)

    def unicode_to_bytes(msg):
        return msg.encode(locale.getpreferredencoding(), errors='backslashreplace')

    if log_func is not None:
        log_func("Control Identifiers:")
        print_identifiers([this_ctrl, ], log_func=log_func)

    elif filename is None:

        def log_func(msg):
            bytestring = unicode_to_bytes(msg)
            print(bytestring)

        print("Control Identifiers:")
        print_identifiers([this_ctrl, ], log_func=log_func)

    else:
        log_file = open(filename, "wb")

        def log_func(msg):
            bytestring = unicode_to_bytes(msg)
            log_file.write(bytestring + os.linesep)

        log_func("Control Identifiers:")
        print_identifiers([this_ctrl, ], log_func=log_func)
        log_file.close()


#=========================================================================
def find_element(**kwargs):
    """
    Call find_elements and ensure that only one element is returned

    Calls find_elements with exactly the same arguments as it is called with
    so please see :py:func:`find_elements` for the full parameters description.
    """
    elements = find_elements(**kwargs)

    if not elements:
        raise ElementNotFoundError(kwargs)

    if len(elements) > 1:
        exception = ElementAmbiguousError(
            "There are {0} elements that match the criteria {1}".format(
                len(elements),
                six.text_type(kwargs),
            )
        )

        exception.elements = elements
        raise exception

    return elements[0]


#=========================================================================
def find_window(**kwargs):
    """
    Call find_elements and ensure that only handle of one element is returned

    Calls find_elements with exactly the same arguments as it is called with
    so please see :py:func:`find_elements` for the full parameters description.
    """
    try:
        kwargs['backend'] = 'win32'
        element = find_element(**kwargs)
        return element.handle
    except ElementNotFoundError:
        raise WindowNotFoundError
    except ElementAmbiguousError:
        raise WindowAmbiguousError


#=========================================================================
def find_elements(class_name=None,
                  class_name_re=None,
                  parent=None,
                  process=None,
                  title=None,
                  title_re=None,
                  top_level_only=True,
                  visible_only=True,
                  enabled_only=False,
                  best_match=None,
                  handle=None,
                  ctrl_index=None,
                  found_index=None,
                  predicate_func=None,
                  active_only=False,
                  control_id=None,
                  control_type=None,
                  auto_id=None,
                  framework_id=None,
                  backend=None,
                  depth=None
                  ):
    """
    Find elements based on criteria passed in

    WARNING! Direct usage of this function is not recommended! It's a very low level API.
    Better use Application and WindowSpecification objects described in the
    Getting Started Guide.

    Possible values are:

    * **class_name**     Elements with this window class
    * **class_name_re**  Elements whose class matches this regular expression
    * **parent**         Elements that are children of this
    * **process**        Elements running in this process
    * **title**          Elements with this text
    * **title_re**       Elements whose text matches this regular expression
    * **top_level_only** Top level elements only (default=**True**)
    * **visible_only**   Visible elements only (default=**True**)
    * **enabled_only**   Enabled elements only (default=False)
    * **best_match**     Elements with a title similar to this
    * **handle**         The handle of the element to return
    * **ctrl_index**     The index of the child element to return
    * **found_index**    The index of the filtered out child element to return
    * **predicate_func** A user provided hook for a custom element validation
    * **active_only**    Active elements only (default=False)
    * **control_id**     Elements with this control id
    * **control_type**   Elements with this control type (string; for UIAutomation elements)
    * **auto_id**        Elements with this automation id (for UIAutomation elements)
    * **framework_id**   Elements with this framework id (for UIAutomation elements)
    * **backend**        Back-end name to use while searching (default=None means current active backend)
    """
    if backend is None:
        backend = registry.active_backend.name
    backend_obj = registry.backends[backend]

    # allow a handle to be passed in
    # if it is present - just return it
    if handle is not None:
        return [backend_obj.element_info_class(handle), ]

    if isinstance(parent, backend_obj.generic_wrapper_class):
        parent = parent.element_info
    elif isinstance(parent, six.integer_types):
        # check if parent is a handle of element (in case of searching native controls)
        parent = backend_obj.element_info_class(parent)

    if top_level_only:
        # find the top level elements
        element = backend_obj.element_info_class()
        elements = element.children(process=process,
                                    class_name=class_name,
                                    title=title,
                                    control_type=control_type,
                                    cache_enable=True)

        # if we have been given a parent
        if parent:
            elements = [elem for elem in elements if elem.parent == parent]

    # looking for child elements
    else:
        # if not given a parent look for all children of the desktop
        if not parent:
            parent = backend_obj.element_info_class()

        # look for ALL children of that parent
        elements = parent.descendants(class_name=class_name,
                                      title=title,
                                      control_type=control_type,
                                      cache_enable=True,
                                      depth=depth)

        # if the ctrl_index has been specified then just return
        # that control
        if ctrl_index is not None:
            return [elements[ctrl_index], ]

    # early stop
    if not elements:
        if found_index is not None:
            if found_index > 0:
                raise ElementNotFoundError("found_index is specified as {0}, but no windows found".format(
                    found_index))
        return elements

    if framework_id is not None and elements:
        elements = [elem for elem in elements if elem.framework_id == framework_id]

    if control_id is not None and elements:
        elements = [elem for elem in elements if elem.control_id == control_id]

    if active_only:
        # TODO: re-write to use ElementInfo interface
        gui_info = win32structures.GUITHREADINFO()
        gui_info.cbSize = ctypes.sizeof(gui_info)

        # get all the active elements (not just the specified process)
        ret = win32functions.GetGUIThreadInfo(0, ctypes.byref(gui_info))

        if not ret:
            raise ctypes.WinError()

        found_active = False
        for elem in elements:
            if elem.handle == gui_info.hwndActive:
                found_active = True
                elements = [elem, ]
                break
        if not found_active:
            elements = []

    if class_name is not None:
        elements = [elem for elem in elements if elem.class_name == class_name]

    if class_name_re is not None:
        class_name_regex = re.compile(class_name_re)
        elements = [elem for elem in elements if class_name_regex.match(elem.class_name)]

    if process is not None:
        elements = [elem for elem in elements if elem.process_id == process]

    if auto_id is not None and elements:
        elements = [elem for elem in elements if elem.automation_id == auto_id]

    if title is not None:
        # TODO: some magic is happenning here
        if elements:
            elements[0].rich_text
        elements = [elem for elem in elements if elem.rich_text == title]
    elif title_re is not None:
        title_regex = re.compile(title_re)

        def _title_match(w):
            """Match a window title to the regexp"""
            t = w.rich_text
            if t is not None:
                return title_regex.match(t)
            return False
        elements = [elem for elem in elements if _title_match(elem)]

    if visible_only:
        elements = [elem for elem in elements if elem.visible]

    if enabled_only:
        elements = [elem for elem in elements if elem.enabled]

    if best_match is not None:
        # Build a list of wrapped controls.
        # Speed up the loop by setting up local pointers
        wrapped_elems = []
        add_to_wrp_elems = wrapped_elems.append
        wrp_cls = backend_obj.generic_wrapper_class
        for elem in elements:
            try:
                add_to_wrp_elems(wrp_cls(elem))
            except (controls.InvalidWindowHandle,
                    controls.InvalidElement):
                # skip invalid handles - they have dissapeared
                # since the list of elements was retrieved
                continue
        elements = findbestmatch.find_best_control_matches(best_match, wrapped_elems)

        # convert found elements back to ElementInfo
        backup_elements = elements[:]
        elements = []
        for elem in backup_elements:
            if hasattr(elem, "element_info"):
                elem.element_info.set_cache_strategy(cached=False)
                elements.append(elem.element_info)
            else:
                elements.append(backend_obj.element_info_class(elem.handle))
    else:
        for elem in elements:
            elem.set_cache_strategy(cached=False)

    if predicate_func is not None:
        elements = [elem for elem in elements if predicate_func(elem)]

    # found_index is the last criterion to filter results
    if found_index is not None:
        if found_index < len(elements):
            elements = elements[found_index:found_index + 1]
        else:
            raise ElementNotFoundError("found_index is specified as {0}, but {1} window/s found".format(
                found_index, len(elements)))

    return elements


#=========================================================================
def find_windows(**kwargs):
    """
    Find elements based on criteria passed in and return list of their handles

    Calls find_elements with exactly the same arguments as it is called with
    so please see :py:func:`find_elements` for the full parameters description.
    """
    try:
        kwargs['backend'] = 'win32'
        elements = find_elements(**kwargs)
        return [elem.handle for elem in elements]
    except ElementNotFoundError:
        raise WindowNotFoundError


#=========================================================================
def enum_windows():
    """Return a list of handles of all the top level windows"""
    windows = []

    # The callback function that will be called for each HWND
    # all we do is append the wrapped handle
    def enum_window_proc(hwnd, lparam):
        """Called for each window - adds handles to a list"""
        windows.append(hwnd)
        return True

    # define the type of the child procedure
    enum_win_proc_t = ctypes.WINFUNCTYPE(
        ctypes.c_int, ctypes.c_long, ctypes.c_long)

    # 'construct' the callback with our function
    proc = enum_win_proc_t(enum_window_proc)

    # loop over all the children (callback called for each)
    win32functions.EnumWindows(proc, 0)

    # return the collected wrapped windows
    return windows
