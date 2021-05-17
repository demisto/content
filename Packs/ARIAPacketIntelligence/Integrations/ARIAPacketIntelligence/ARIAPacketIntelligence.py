import demistomock as demisto
from CommonServerPython import *
import json
import requests
import time
import re


class ParameterError(Exception):
    """ Raised when the function parameters do not meet requirements """
    pass


"""
Remediation Configuration String (RCS) that use to select SIA.
"""


class RCS:
    """
    Define class members

    Define class methods
    """

    def __init__(self, rcs=None):
        self.rcs = rcs
        if self.rcs is None:
            self.rcs = "PIdevice@all"

        """
        Used to indicate which RET types currently supported
        """
        self.RET_functions = {"drop": self._parse_RET_drop}

    """
    destructor
    """
    def __del__(self):
        return 0

    """
    Parse a drop command and return its representation
    for being put into a NRDO action / rule.
    """
    def _parse_RET_drop(self, rcs):
        if rcs is None:
            return None, None
        elif rcs == "":
            return None, None

        rcsp = re.match("^[(][)](.+)$", rcs)
        if rcsp is None:
            return None, rcs
        elif rcsp.group(1) is None:
            return "", None
        elif rcsp.group(1) == "":
            return "", None

        RET_drop = ["drop"]

        return RET_drop, rcsp.group(1)

    """
    Parse a SIA simple name
    """
    def _parse_RDL_RD_name(self, rcs):
        if rcs is None:
            return None, None, "failed: RD name rcs none"
        elif rcs == "":
            return None, None, "failed: RD name rcs empty"

        rcsp = re.match(r"^(\w[\w-]*)(.*)$", rcs)
        if rcsp is None:
            return None, None, "failed: RD name match none"
        elif rcsp.group(1) is None:
            return None, None, "failed: RD name none"
        elif rcsp.group(1) == "":
            return None, None, "failed: RD name empty"

        RD_name = ("name", rcsp.group(1))

        rcs = rcsp.group(2)

        return RD_name, rcs, "success: {0}".format(rcsp.group(1))

    """
    Parse a FQN
    """
    def _parse_RDL_RD_FQN(self, rcs):
        if rcs is None:
            return None, None, "failed: RD fqn rcs none"
        elif rcs == "":
            return None, None, "failed: RD fqn rcs empty"

        rcsp = re.match("^([<][\w_-<>.]+[>])(.*)$", rcs)
        if rcsp is None:
            return None, None, "failed: RD fqn match none"
        elif rcsp.group(1) is None:
            return None, None, "failed: RD fqn none"
        elif rcsp.group(1) == "":
            return None, None, "failed: RD fqn empty"

        RD_fqn = ("FQN", rcsp.group(1))

        rcs = rcsp.group(2)

        return RD_fqn, rcs, "success: {0}".format(rcsp.group(1))

    """
    Parse a security domain name SDN
    """
    def _parse_RDL_RD_SDN(self, rcs):
        if rcs is None:
            return None, None, "failed: RD sd rcs none"
        elif rcs == "":
            return None, None, "failed: RD sd rcs empty"

        rcsp = re.match("^\^(\w[\w-]*)(.*)$", rcs)
        if rcsp is None:
            return None, None, "failed: RD sd match none"
        elif rcsp.group(1) is None:
            return None, None, "failed: RD sd none"
        elif rcsp.group(1) == "":
            return None, None, "failed: RD sd empty"

        RD_sdn = ("securityDomain", rcsp.group(1))

        rcs = rcsp.group(2)

        return RD_sdn, rcs, "success: {0}".format(rcsp.group(1))

    """
    Parse an RGN label as a name
    """
    def _parse_RDL_RD_RGN_name(self, rcs):
        if rcs is None:
            return None, None, "failed: RD rgn name rcs none"
        elif rcs == "":
            return None, None, "failed: RD rgn name rcs empty"

        rcsp = re.match(r"^(\w[\w-]*)(.*)$", rcs)
        if rcsp is None:
            return None, None, "failed: RD rgn name rcsp none"
        elif rcsp.group(1) is None:
            return None, None, "failed: RD rgn name rcsp.g1 none"
        elif rcsp.group(1) == "":
            return None, None, "failed: RD rgn name rcsp.g1 empty"

        return rcsp.group(1), rcsp.group(2), "success"

    """
    Parse an RGN label as a list of names
    """
    def _parse_RDL_RD_RGN_list(self, rcs):
        if rcs is None:
            return None, None, "failed: RD rgn list rcs none"
        elif rcs == "":
            return None, None, "failed: RD rgn list rcs empty"

        rcsp = re.match(r"^[(](.+)$", rcs)
        if rcsp is None:
            return None, None, "failed: RD rgn list rcsp none"
        elif rcsp.group(1) is None:
            return None, None, "failed: RD rgn list rcsp.g1 none"
        elif rcsp.group(1) == "":
            return None, None, "failed: RD rgn list rcsp.g1 empty"

        rcs = rcsp.group(1)

        names = ""

        while True:
            rcsp = re.match(r"(\w[\w-]*)(.+)$", rcs)
            if rcsp is None:
                return None, None, "failed: RD rgn list rcsp name none"
            elif rcsp.group(1) is None:
                return None, None, "failed: RD rgn list rcsp.g1 name none"
            elif rcsp.group(1) == "":
                return None, None, "failed: RD rgn list rcsp.g1 name empty"

            names = "{0}{1}".format(names, rcsp.group(1))

            rcs = rcsp.group(2)
            if rcs is None:
                return None, None, "failed: RD rgn list rcsp.g2 name none"
            elif rcs == "":
                return None, None, "failed: RD rgn list rcsp.g2 name empty"

            rcsp = re.match("^[)](.*)$", rcs)
            if rcsp is not None:
                rcs = rcsp.group(1)
                break

            rcsp = re.match("^,(.+)$", rcs)
            if rcsp is None:
                return None, None, "failed: RD rgn list rcsp comma none"
            elif rcsp.group(1) is None:
                return None, None, "failed: RD rgn list rcsp.g1 comma none"
            elif rcsp.group(1) == "":
                return None, None, "failed: RD rgn list rcsp.g1 comma empty"

            rcs = rcsp.group(1)

            names = "{},".format(names)

        if names == "":
            return None, None, "failed: RD rgn list names empty"

        names = "({})".format(names)

        return names, rcs, "success: {0}".format(names)

    """
    Parse an RGN label as asterik
    """
    def _parse_RDL_RD_RGN_asterik(self, rcs):
        if rcs is None:
            return None, None, "failed: RD rgn asterik rcs none"
        elif rcs == "":
            return None, None, "failed: RD rgn asterik rcs empty"

        rcsp = re.match("^\*(.*)$", rcs)
        if rcsp is None:
            return None, None, "failed: RD rgn asterik rcsp none"

        return "*", rcsp.group(1), "success"

    """
    Parse an RGN
    """
    def _parse_RDL_RD_RGN_label(self, rcs):
        if rcs is None:
            return None, None, "failed: RD label rgn rcs none"
        elif rcs == "":
            return None, None, "failed: RD label rgn rcs empty"

        while True:
            rcsp = re.match(r"^[!]([(].*)$", rcs)
            if rcsp is not None:
                if rcsp.group(1) is None:
                    return None, None, "failed: RD rgn label exclusive g1 none"
                elif rcsp.group(1) == "":
                    return None, None, "failed: RD rgn label exclusive g1 empty"
                rcs = rcsp.group(1)
                label, rcs, msg = self._parse_RDL_RD_RGN_list(rcs)
                if label is None:
                    return None, None, "failed: RD rgn label exclusive none {0}".format(msg)
                elif label == "":
                    return None, None, "failed: RD rgn label exclusive empty {0}".format(msg)
                label = "!{0}".format(label)
                break

            rcsp = re.match(r"^[(].*$", rcs)
            if rcsp is not None:
                label, rcs, msg = self._parse_RDL_RD_RGN_list(rcs)
                if label is None:
                    return None, None, "failed: RD rgn label inclusive none {0}".format(msg)
                elif label == "":
                    return None, None, "failed: RD rgn label inclusive empty {0}".format(msg)
                break

            rcsp = re.match("^\*.*$", rcs)
            if rcsp is not None:
                label, rcs, msg = self._parse_RDL_RD_RGN_asterik(rcs)
                if label is None:
                    return None, None, "failed: RD rgn label asterik none {0}".format(msg)
                elif label == "":
                    return None, None, "failed: RD rgn label asterik empty {0}".format(msg)
                break

            rcsp = re.match(r"^[\w].*$", rcs)
            if rcsp is not None:
                label, rcs, msg = self._parse_RDL_RD_RGN_name(rcs)
                if label is None:
                    return None, None, "failed: RD rgn label name none {0}".format(msg)
                elif label == "":
                    return None, None, "failed: RD rgn label name empty {0}".format(msg)
                break

            return None, None, "failed: RD rgn label invalid"

        return label, rcs, "success"

    """
    Parse an RGN
    """
    def _parse_RDL_RD_RGN(self, rcs):
        if rcs is None:
            return None, None, "failed: RD rgn rcs none"
        elif rcs == "":
            return None, None, "failed: RD rgn rcs empty"

        region, rcs, msg = self._parse_RDL_RD_RGN_label(rcs)
        if region is None:
            return None, None, "failed: RD rgn region none {0}".format(msg)
        elif region == "":
            return None, None, "failed: RD rgn region empty {0}".format(msg)
        elif rcs is None:
            return None, None, "failed: RD rgn region rcs none {0}".format(msg)
        elif rcs == "":
            return None, None, "failed: RD rgn region rcs empty {0}".format(msg)

        rcsp = re.match("^\.(.+)$", rcs)
        if rcsp is None:
            return None, None, "failed: RD rgn region rcsp none ."
        elif rcsp.group(1) is None:
            return None, None, "failed: RD rgn region rcsp.g1 none ."
        elif rcsp.group(1) == "":
            return None, None, "failed: RD rgn region rcsp.g1 empty ."
        rcs = rcsp.group(1)

        group, rcs, msg = self._parse_RDL_RD_RGN_label(rcs)
        if group is None:
            return None, None, "failed: RD rgn group none {0}".format(msg)
        elif group == "":
            return None, None, "failed: RD rgn group empty {0}".format(msg)
        elif rcs is None:
            return None, None, "failed: RD rgn group rcs none {0}".format(msg)
        elif rcs == "":
            return None, None, "failed: RD rgn group rcs empty {0}".format(msg)

        rcsp = re.match("^\.(.+)$", rcs)
        if rcsp is None:
            return None, None, "failed: RD rgn group rcsp none ."
        elif rcsp.group(1) is None:
            return None, None, "failed: RD rgn group rcsp.g1 none ."
        elif rcsp.group(1) == "":
            return None, None, "failed: RD rgn group rcsp.g1 empty ."
        rcs = rcsp.group(1)

        name, rcs, msg = self._parse_RDL_RD_RGN_label(rcs)
        if name is None:
            return None, None, "failed: RD rgn name none {0}".format(msg)
        elif name == "":
            return None, None, "failed: RD rgn name empty {0}".format(msg)

        RGN = ("RGN", "{0}.{1}.{2}".format(region, group, name))

        return RGN, rcs, "success"

    """
     parse the RDL component of the RCS:
       RDL      :: PIdevice@[<RD><RD_LIST>*]
       RD       :: name | SDN | RGN | FQN
       RD_LIST  :: , <RD>
    """
    def _parse_RDL(self, rcs):
        if rcs is None:
            return None, None, "failed: rcs is none"
        elif rcs == "":
            return None, None, "failed: rcs is empty"

        rcsp = re.match("^PIdevice@(.*)$", rcs)
        if rcsp is None:
            return None, rcs, "failure: invalid keyword"

        RDL_all = ("RGN", "all.all.all")
        RDL = []

        if rcsp.group(1) is None:
            return RDL_all, None, "success: all (none)"
        elif rcsp.group(1) == "":
            return RDL_all, None, "success: all (empty)"

        rcs = rcsp.group(1)

        while True:
            if rcs is None:
                break
            elif rcs == "":
                break

            while True:
                rcsp = re.match("^all\..+$", rcs)
                if rcsp is not None:
                    if rcsp.group(0) == "":
                        return None, None, "failure: RGN (all-none)"
                    RD, rcs, msg = self._parse_RDL_RD_RGN(rcs)
                    if RD is None:
                        return None, None, "failure: RGN (all-obj) {0}".format(msg)
                    elif len(RD) != 2:
                        return None, None, "failure: RGN (all len != 2) {0}".format(msg)
                    RDL.append(RD)
                    break

                rcsp = re.match(r"^all(.*)$", rcs)
                if rcsp is not None:
                    if rcsp.group(0) == "":
                        return None, None, "failure: all (empty)"
                    RDL.append(RDL_all)
                    rcs = rcsp.group(1)
                    break

                rcsp = re.match("^\^.*$", rcs)
                if rcsp is not None:
                    if rcsp.group(0) == "":
                        return None, None, "failure: SD (none)"
                    RD, rcs, msg = self._parse_RDL_RD_SDN(rcs)
                    if RD is None:
                        return None, None, "failure: SD (empty) {0}".format(msg)
                    elif len(RD) != 2:
                        return None, None, "failure: SD (len != 2) {0}".format(msg)
                    RDL.append(RD)
                    break

                rcsp = re.match(r"^[<].*$", rcs)
                if rcsp is not None:
                    if rcsp.group(0) == "":
                        return None, None, "failure: FQN (empty)"
                    RD, rcs, msg = self._parse_RDL_RD_FQN(rcs)
                    if RD is None:
                        return None, None, "failure: FQN (obj) {0}".format(msg)
                    elif len(RD) != 2:
                        return None, None, "failure: FQN (len != 2) {0}".format(msg)
                    RDL.append(RD)
                    break

                rcsp = re.match(r"^[!].*$", rcs)
                if rcsp is not None:
                    if rcsp.group(0) == "":
                        return None, None, "failure: RGN (exclusive-none)"
                    RD, rcs, msg = self._parse_RDL_RD_RGN(rcs)
                    if RD is None:
                        return None, None, "failure: RGN (exclusive-obj) {0}".format(msg)
                    elif len(RD) != 2:
                        return None, None, "failure: RGN (exclusive len != 2) {0}".format(msg)
                    RDL.append(RD)
                    break

                rcsp = re.match(r"^[(].*$", rcs)
                if rcsp is not None:
                    if rcsp.group(0) == "":
                        return None, None, "failure: RGN (inclusive-none)"
                    RD, rcs, msg = self._parse_RDL_RD_RGN(rcs)
                    if RD is None:
                        return None, None, "failure: RGN (inclusive-none) {0}".format(msg)
                    elif len(RD) != 2:
                        return None, None, "failure: RGN (inclusive len != 2) {0}".format(msg)
                    RDL.append(RD)
                    break

                rcsp = re.match("^\*\..*$", rcs)
                if rcsp is not None:
                    if rcsp.group(0) == "":
                        return None, None, "failure: RGN (asterik-none)"
                    RD, rcs, msg = self._parse_RDL_RD_RGN(rcs)
                    if RD is None:
                        return None, None, "failure: RGN (asterik-none) {0}".format(msg)
                    elif len(RD) != 2:
                        return None, None, "failure: RGN (asterik len != 2) {0}".format(msg)
                    RDL.append(RD)
                    break

                rcsp = re.match("^\*(.*)$", rcs)
                if rcsp is not None:
                    if rcsp.group(0) == "":
                        return None, None, "failure: asterik (empty)"
                    RDL.append(RDL_all)
                    rcs = rcsp.group(1)
                    break

                rcsp = re.match(r"^[\w].*$", rcs)
                if rcsp is None:
                    return None, None, "failure: name should be there"

                rcsp = re.match("^\w[\w-]*\..*$", rcs)
                if rcsp is not None:
                    if rcsp.group(0) == "":
                        return None, None, "failure: name RGN (none)"
                    RD, rcs, msg = self._parse_RDL_RD_RGN(rcs)
                    if RD is None:
                        return None, None, "failure: RGN name (obj) {0}".format(msg)
                    elif len(RD) != 2:
                        return None, None, "failure: RGN name (len != 2) {0}".format(msg)
                    RDL.append(RD)
                    break

                RD, rcs, msg = self._parse_RDL_RD_name(rcs)
                if RD is None:
                    return None, None, "failure: NAME (obj) {0}".format(msg)
                elif len(RD) != 2:
                    return None, None, "failure: NAME (len != 2) {0}".format(msg)
                RDL.append(RD)
                break

            if rcs is None:
                break
            elif rcs == "":
                break

            rcsp = re.match("^,(.*)$", rcs)
            if rcsp is None:
                return None, None, "failure: RDL , obj (none)"
            elif rcsp.group(1) is None:
                return None, None, "failure: RDL , (none)"
            elif rcsp.group(1) == "":
                return None, None, "failure: RDL , (empty)"
            rcs = rcsp.group(1)

        if rcs is not None:
            if rcs != "":
                return None, "", "failure: RCS ended-!empty"

        if len(RDL) <= 0:
            return None, None, "failure: RDL empty"

        return RDL, None, "success: {0}".format(len(RDL))

    """
     parse the RET component of the RCS:
       RET      :: Remediation@<ret><ret_list>
       ret      :: drop() | alert(...) | redirect(...) | serviceChain(...)
       SDN_LIST :: , <ret>
    """
    def _parse_RET(self, rcs):
        if rcs is None:
            return None, None, "failure: RET RCS none"
        elif rcs == "":
            return None, None, "failure: RET RCS empty"

        rcsp = re.match("^Remediation@(.+)$", rcs)
        if rcsp is None:
            rcs = "Remediation@drop()${0}".format(rcs)
            rcsp = re.match("^Remediation@(.+)$", rcs)
            if rcsp is None:
                return None, rcs, "failure: RET failed insert drop()"

        if rcsp.group(1) is None:
            return None, None, "failuure: RET obj none"
        elif rcsp.group(1) == "":
            return None, None, "failure: RET obj empty"

        rcs = rcsp.group(1)
        RET = []

        rcsp = re.match("^\$(.+)$", rcs)
        if rcsp is not None:
            rcs = "drop(){0}".format(rcs)

        while True:
            rcsp = re.match("(\w[\w]*)([(].+\$.+)$", rcs)
            if rcsp is None:
                return None, None, "failure: RET obj type none"
            elif rcsp.group(1) is None:
                return None, None, "failure: RET type none"
            elif rcsp.group(1) == "":
                return None, None, "failure: RET type empty"

            RET_parse_func = self.RET_functions.get(rcsp.group(1))
            if RET_parse_func is None:
                return None, None, "failure: RET type not found"

            rcs = rcsp.group(2)
            if rcs is None:
                return None, None, "failure: RET RCS none"
            elif rcs == "":
                return None, None, "failure: RET RCS empty"

            """
             call the RET type parser to create
             its PI object.
            """
            obj, rcs = RET_parse_func(rcs)
            if obj is None:
                return None, None, "failure: RET func obj none"
            elif len(obj) < 1:
                return None, None, "failure: RET func obj 1 or greater"
            elif rcs is None:
                return None, None, "failure: RET func RCS none"
            elif rcs == "":
                return None, None, "failure: RET func RCS empty"

            RET.append(obj)

            rcsp = re.match("^\$(.+)$", rcs)
            if rcsp is not None:
                break

            rcsp = re.match("^,(\w[\w]*[(].+\$.+)$", rcs)
            if rcsp is None:
                return None, None, "failure: RET next obj none"
            elif rcsp.group(1) is None:
                return None, None, "failure: RET next none"
            elif rcsp.group(1) == "":
                return None, None, "failure: RET next empty"

            rcs = rcsp.group(1)

        if rcs is None:
            return None, None, "failure: RET end RCS none"
        elif rcs == "":
            return None, None, "failure: RET end RCS empty"

        rcsp = re.match("^\$(.+)$", rcs)
        if rcsp is None:
            return None, None, "failure: RET # remove none"
        elif rcsp.group(1) is None:
            return None, None, "failure: RET # remove group none"
        elif rcsp.group(1) == "":
            return None, None, "failure: RET # remove group empty"

        rcs = rcsp.group(1)

        if len(RET) <= 0:
            return None, None, "failure: RET list empty"

        return RET, rcs, "success: {0}".format(len(RET))

    """
     parse the SDL component of the RCS:
       SDL      :: securityDomain@<SDN><SDN_LIST>*
       SDN      :: <a-zA-Z0-9_><a-zA-Z0-9_>*
       SDN_LIST :: , <SDN>
    """
    def _parse_SDL(self, rcs):
        if rcs is None:
            return None, None, "failure: RCS is none"
        elif rcs == "":
            return None, None, "failure: RCS is empty"

        rcsp = re.match("^securityDomain@(.+)$", rcs)
        if rcsp is None:
            SDL = ["all"]
            return SDL, rcs, "success: 1"

        if rcsp.group(1) is None:
            return None, None, "failure: none"
        elif rcsp.group(1) == "":
            return None, None, "failure: empty"

        rcs = rcsp.group(1)
        SDL = []

        while True:
            rcsp = re.match("(\w[\w-]*)(.*\$.+)$", rcs)
            if rcsp is None:
                return None, None, "failure: bad SDN"
            elif rcsp.group(1) is None:
                return None, None, "failure: SDN none"
            elif rcsp.group(1) == "":
                return None, None, "failure: SDN empty"

            SDL.append(rcsp.group(1))

            rcs = rcsp.group(2)
            if rcs is None:
                return None, None, "failure: SDN no more RCS none"
            elif rcs == "":
                return None, None, "failure: SDN no more RCS empty"

            rcsp = re.match("^\$(.+)$", rcs)
            if rcsp is not None:
                break

            rcsp = re.match("^,(\w[\w-]*.*\$.+)$", rcs)
            if rcsp is None:
                return None, None, "failure: SDN obj advance none"
            elif rcsp.group(1) is None:
                return None, None, "failure: SDN advance none"
            elif rcsp.group(1) == "":
                return None, None, "failure: SDN advance empty"

            rcs = rcsp.group(1)

        if rcs is None:
            return None, None, "failure: SDL RCS none"
        elif rcs == "":
            return None, None, "failure: SDL RCS empty"

        rcsp = re.match("^\$(.+)$", rcs)
        if rcsp is None:
            return None, None, "failure: SDL # remove none"
        elif rcsp.group(1) is None:
            return None, None, "failure: SDL # remove group none"
        elif rcsp.group(1) == "":
            return None, None, "failure: SDL # remove group empty"
        rcs = rcsp.group(1)

        if len(SDL) <= 0:
            return None, None, "failure: SDL list empty"

        return SDL, rcs, "success: {0}".format(len(SDL))

    """
    Parse out the components of the RCS: [SDL] | [RET] | RDL
    and return all three. If the optional component is
    not found then it returns None but if keyword is
    found nothing else then returns empty.

    The fourth result returned is if there is remaining characters
    in the original RCS then its returned.

    Returns info in fifth result
    """
    def _parse(self, rcs):
        if rcs is None:
            return None, None, None, None, "failed: RCS is none"
        elif rcs == "":
            return None, None, None, None, "failed: RCS is empty"

        rcsp = re.search(" ", rcs)
        if rcsp is not None:
            return None, None, None, None, "failed: space character found in RCS"

        SDL, rcs_next, msg = self._parse_SDL(rcs)
        if SDL is not None:
            if len(SDL) <= 0:
                return None, None, None, None, "failed: SDL returned but is empty (msg={0})".format(msg)
        if rcs_next is None:
            return SDL, None, None, None, "failed: RCS invalid parse after SDL (none) (msg={0})".format(msg)
        elif rcs_next == "":
            return SDL, None, None, None, "failed: RCS invalid parse after SDL (empty) (msg={0})".format(msg)

        RET, rcs_next, msg = self._parse_RET(rcs_next)
        if RET is None:
            return SDL, None, None, None, "failed: RET is none (msg={0})".format(msg)
        elif len(RET) <= 0:
            return SDL, None, None, None, "failed: RET is empty (msg={0})".format(msg)
        elif rcs_next is None:
            return SDL, RET, None, None, "failed: RCS invalid parse after RET (none) (msg={0})".format(msg)
        elif rcs_next == "":
            return SDL, RET, None, None, "failed: RCS invalid parse after RET (none) (msg={0})".format(msg)

        RDL, rcs_next, msg = self._parse_RDL(rcs_next)
        if RDL is None:
            return SDL, RET, None, None, "failed: RDL is none (msg={0})".format(msg)
        elif len(RDL) <= 0:
            return SDL, RET, None, None, "failed: RDL is empty (msg={0})".format(msg)
        elif rcs_next is not None:
            if rcs_next != "":
                return SDL, RET, RDL, None, "failed: RCS invalid parse after RDL (not empty) (msg={0})".format(msg)

        return SDL, RET, RDL, rcs_next, "success"

    """
     Returns true if the RCS provided at object instantiation
     time is a valid RCS value, otherwise it returns false.
    """
    def _valid(self, rcs):
        if rcs is None:
            return False

        # rcs_save = rcs

        SDL, RET, RDL, rcs, rmsg = self._parse(rcs)
        if RDL is None:
            # print("ARIA: remediation configuraton string (RCS) is invalid -- this will prevent remediation
            # to ARIA PI devices from working (rcs={0}:: rmsg={1})".format(rcs_save, rmsg))
            return False

        # print("ARIA: remediation configuraton string (RCS) is valid (rcs={0})".format(rcs_save))

        return True

    """
    Returns true if the RCS provided at object instantiation
    time is a valid RCS value, otherwise it returns false.
    """
    def valid(self):
        if not self._valid(self.rcs):
            return False

        return True

    """
    Allows setting the RCS string to act on, this will only
    set it if the string is already empty.  Otherwise it
    should use modify.
    """
    def set(self, rcs):
        if self.rcs is None:
            if not self._valid(rcs):
                return False
            self.rcs = rcs
        else:
            return False

        return True

    """
    Allows changing the RCS string after its been previsouly
    set or not.
    """
    def modify(self, rcs):
        if not self._valid(rcs):
            return False

        self.rcs = rcs

        return True

    """
    Assuming the securtiy domain component of the RCS is valid
    then it returns the parsed out security domain component if
    it exists. It will return it as a list of security domain
    object name strings.

    If there is an error in parsing the security domain component
    null is returned.  If it was not provided then "all"
    list is returned.
    """
    def security_domain(self):
        SDL, RET, RDL, rcs, rmsg = self._parse(self.rcs)
        if RDL is None:
            return None, False

        return SDL, True

    """
    Assuming the RCS is valid
    then return the RDL

    If there is an error in parsing the RDL component is
    returned as a NULL.
    """

    def remediation_device_list(self):
        SDL, RET, RDL, rcs, rmsg = self._parse(self.rcs)
        if RDL is None:
            return None, False

        return RDL, True

    """
    Assuming the securtiy domain component of the RCS is valid

    Assuming the RCS is valid
    then return the remediation action instruction.

    If there is an error in parsing the RET component is
    returned as a NULL.
    """

    def remediation_instruction(self):
        SDL, RET, RDL, rcs, rmsg = self._parse(self.rcs)
        if RDL is None:
            return None, False

        return RET, True


class ARIA(object):

    def __init__(self, sdso_url: str, verify_cert: bool = True):
        self.sdso_url = sdso_url
        self.time_out = 20
        self.verify_cert = verify_cert

    """HELPER FUNCTION"""

    @staticmethod
    def _build_alert_instruction(transport_type: str, tti_index: int, aio_index: int,
                                 trigger_type: str, trigger_value: int) -> str:
        """ Create an alert instruction

        Args:
            transport_type: The type of notification to generate.
                Valid values are 'email', 'SMS', 'syslog' or 'webhook'.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.

        Returns: Alert instruction string.

        Raises:
            ValueError: If parameters are out of range or not in the type list.

        """
        transport_type_list = ['email', 'SMS', 'syslog', 'webhook']

        if transport_type not in transport_type_list:
            raise ValueError(f'Wrong transport_type {transport_type}! Valid values are email, SMS, syslog or webhook')

        if tti_index > 7 or tti_index < 0:
            # This is an ARIA PI Reaper production requirement
            raise ValueError('Transport type info index(tti_index) out of range! '
                             'Valid value must be in the range [0, 7].')

        if aio_index > 15 or aio_index < 0:
            # This is an ARIA PI Reaper production requirement
            raise ValueError('Alert info object index(aio_index) out of range! '
                             'Valid value must be in range [0, 15]')

        trigger_type_list = ['one-shot', 're-trigger-count', 're-trigger-timed-ms', 're-trigger-timed-sec']

        if trigger_type not in trigger_type_list:
            # This is an ARIA PI Reaper production requirement
            raise ValueError(f'Wrong trigger_type {trigger_type}! Valid values are one-shot, re-trigger-count, '
                             're-trigger-timed-ms, re-trigger-timed-sec')

        if trigger_value < 1 or trigger_value > 8191:
            # This is an ARIA PI Reaper production requirement
            raise ValueError('Trigger value(trigger_value) out of range! It must be in range [1, 8191]')

        instruction = f'ALERT {transport_type} {tti_index} {aio_index} {trigger_type} {trigger_value}'

        return instruction

    @staticmethod
    def _process_port_range(port_range: str = None) -> str:
        """ Validation function for range of ports

        Args:
            port_range: The source or destination port(s). This accepts a
                comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).

        Returns: The string of port_range.

        Raises:
            ValueError: If port_range is out of range 0-65535 or in wrong format.

        """
        if not port_range:
            port_range = '0-65535'  # default port_range value

        split_port_range = port_range.replace(' ', '').split(',')

        res = ''

        for port in split_port_range:
            if res:
                res = res + ', '

            if '-' in port:

                beg, end = port.replace(' ', '').split('-')

                for j in beg, end:
                    if int(j) < 0 or int(j) > 65535:
                        raise ValueError('Port must be in 0-65535!')

                if int(beg) > int(end):
                    raise ValueError('Wrong port range format!')

                res += beg + ' - ' + end
            else:
                if int(port) < 0 or int(port) > 65535:
                    raise ValueError('Port must be in 0-65535!')
                res += port

        return res

    @staticmethod
    def _process_ip_address(ip: str) -> str:
        """ Validation function for IP address

        Args:
            ip: The IP address and mask of the IP address, in the format <IP_address>/<mask>. If the mask is omitted,
                a value of 32 is used.

        Returns: String of IP address.

        Raises:
            ValueError: If the netmask is out of range or IP address is not expressed in CIDR notation

        """
        netmask = '32'

        ip_str = ip.replace(' ', '')

        if '/' in ip_str:
            ip_addr, netmask = ip_str.split('/')
        else:
            ip_addr = ip_str

        if int(netmask) > 32 or int(netmask) < 1:
            raise ValueError('Subnet mask must be in range [1, 32].')

        ip_addr_split = ip_addr.split('.')
        for syllable in ip_addr_split:
            if int(syllable) < 0 or int(syllable) > 255:
                raise ValueError('Wrong IP format!')
        if len(ip_addr_split) != 4:
            raise ValueError('Wrong IP format!')
        res = ip_addr + '/' + netmask
        return res

    @staticmethod
    def _parse_rcs(rcs):
        """ Parse Remediation Configuration String

        Args:
            rcs: Remediation Configuration String.

        Returns:
            sd_list: List of securityDomain Object
            sia_list: List of securityDomain SIA Object

        Raises:
            ParameterError: Raised when Input RCS is not valid.

        """
        rcs = RCS(rcs)
        if not rcs.valid():
            raise ParameterError('Your Input RCS is not valid!')
        sd_list_tuple, sd_list_valid = rcs.security_domain()
        sd_list = []
        if sd_list_valid:
            for element in sd_list_tuple:
                sd_list.append({"SDN": element})

        sia_list_tuple, sia_list_valid = rcs.remediation_device_list()
        sia_list = []
        sd_list = [{"SDN": "all"}]
        if sia_list_valid:
            for element in sia_list_tuple:
                sia_object = {
                    'sia_specification_type': element[0],
                    'sia_specification': element[1]
                }
                sia_list.append(sia_object)
        return sd_list, sia_list

    @staticmethod
    def _generate_rule_forward_spec(rule_name: str, logic_block: str, rule: str, named_rule_action: str, sd_list: list,
                                    sia_list: list, instance_id: str = None) -> dict:
        """ Generate rule forward spec for ruleforward API

        Args:
            rule_name: The name of the rule to create.
            logic_block: Parameter used to form named rule data. Examples: '5-tuple', 'src-port', etc.
            rule: Parameter used to form named rule data.
            named_rule_action: Must be 'add' or 'remove'
            instance_id: The instance number of the ARIA PI instance.
            sd_list: List of security domain object.
            sia_list: List of security domain sia object.

        Returns: Dictionary data of named rule.

        """
        instance_id_type = 'instance-number'

        if instance_id is None:
            instance_id_type = 'all'
            instance_id = ''

        if named_rule_action == 'remove':
            rule = ''

        named_rule = f'\"name\": \"{rule_name}\", \"logic_block\": \"{logic_block}\", \"rule\": \"{rule}\"'

        named_rule_distribution = {
            'kind': 'NamedRuleDistribution',
            'instance_id': instance_id,
            'instance_id_type': instance_id_type,
            'named_rule': named_rule,
            'named_rule_action': named_rule_action,
            'sd_list': sd_list,
            'sia_list': sia_list
        }

        rule_forward_spec = {
            'selector': named_rule_distribution
        }

        return rule_forward_spec

    def _wait_for_trid(self, trid: str) -> bool:
        """ Valid whether the request completed by trid

        Args:
            trid: The request id when you want to adding a rule to ARIA PI Reaper.

        Returns: True if complete, False if not.

        """

        # url to valid the request
        trid_url = self.sdso_url + f'/packetClassification/completion/transaction?PC_TRID={trid}'

        # Use trid of transaction to get if a transaction success

        t0 = time.perf_counter()

        delta = time.perf_counter() - t0

        while delta < 20:
            res = requests.get(trid_url, timeout=self.time_out, verify=self.verify_cert)

            delta = time.perf_counter() - t0

            if res.ok:
                try:
                    tcl_list = res.json().get('tclList')
                except json.JSONDecodeError:
                    raise

                for tcl_entry in tcl_list:
                    if 'SUCCESS' in tcl_entry['status']:
                        return True
                    elif 'FAILURE' in tcl_entry['status']:
                        return False
            time.sleep(1)

        return False

    def _remove_rule(self, rule_name: str, logic_block: str, instance_id: str = None, rcs: str = None) -> dict:
        """ Remove rule in the ARIA PI Reaper

        Args:
            rule_name: The name of the rule to create.
            logic_block: Parameter used to form named rule data. Examples: '5-tuple', 'src-port', etc.
            instance_id: The instance number of the ARIA PI instance.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """

        url = self.sdso_url + '/ruleForward'

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block=logic_block, rule='no-rule',
                                                named_rule_action='remove', instance_id=instance_id,
                                                sd_list=sd_list, sia_list=sia_list)
        try:
            response = requests.put(url, data=json.dumps(data), headers=headers, timeout=self.time_out,
                                    verify=self.verify_cert)
        except requests.exceptions.RequestException:
            raise

        command_state_str = 'Failure'
        response_timestamp = None
        ep_res = None

        if response and response.ok:
            response_json = response.json()
            endpoints = response_json.get('endpoints')

            if not endpoints or len(endpoints) == 0:
                command_state_str = 'Endpoint matching RCS not found!'
            else:
                command_state_str = 'Success'
                for ep in endpoints:
                    trid = ep.get('trid')
                    status = self._wait_for_trid(str(trid))
                    ep['completion'] = status
                    if not status:
                        command_state_str = 'Failure'
            response_timestamp = response_json.get('timestamp')
            ep_res = endpoints

        context = {
            'Rule': {
                'Name': rule_name,
                'Definition': f'Remove {rule_name}',
                'RCS': rcs
            },
            'Status': {
                'command_state': command_state_str,
                'timestamp': response_timestamp
            },
            'Endpoints': ep_res
        }

        return context

    def _do_request(self, data: dict, rule_name: str, rule: str, rcs: str = None) -> dict:
        """ Send a request to ARIA PI Reaper to create a rule

        Args:
            data: Rule Forward Spec data.
            rule_name: Name of the rule.
            rule: String representation of rule.

        Returns: Dictionary context data contains useful response information.

        """
        url = self.sdso_url + '/ruleForward'

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

        data['selector']['instance_id_type'] = 'instance-number'
        data['selector']['instance_id'] = '0'

        instance_number = 10  # 10 total instances in ARIA PI Reaper

        command_state_str = 'Failure'
        response_timestamp = None
        endpoints = None

        try:
            response = requests.put(url=url, data=json.dumps(data), headers=headers, timeout=self.time_out,
                                    verify=self.verify_cert)
        except requests.exceptions.RequestException:
            raise

        failed_endpoints_index = []
        success_endpoints_index = []
        if response and response.ok:
            response_json = response.json()
            endpoints = response_json.get('endpoints')
            response_timestamp = response_json.get('timestamp')
            if endpoints and len(endpoints) > 0:
                for ep_index, ep in enumerate(endpoints):
                    trid = ep.get('trid')
                    status = self._wait_for_trid(str(trid))
                    # Add completion and instance_number in ep field
                    ep['instance_number'] = '0'
                    ep['completion'] = status
                    if status:
                        success_endpoints_index.append(ep_index)
                    else:
                        failed_endpoints_index.append(ep_index)

            # no endpoints matches
            if len(failed_endpoints_index) == 0 and len(success_endpoints_index) == 0:
                command_state_str = "Endpoint matching RCS not found!"
            # rules are created successfully on all endpoints
            elif len(success_endpoints_index) > 0 and len(failed_endpoints_index) == 0:
                command_state_str = "Success"
            # rules are not created successfully on part or all endpoints, should try to forward rules on
            # different instance for the failed endpoints
            else:
                # forward rule to each endpoints by AgentFQN
                command_state_str = "Success"
                for ep_index in failed_endpoints_index:
                    ep = endpoints[ep_index]
                    AgentFQN = ep.get('AgentFQN')
                    temp_forward_data = data.copy()
                    sia_object = {
                        'sia_specification_type': 'FQN',
                        'sia_specification': AgentFQN
                    }
                    temp_forward_data['selector']['sia_list'] = [sia_object]
                    ep_state = False

                    for i in range(1, instance_number):
                        data['selector']['instance_id'] = str(i)
                        try:
                            ep_response = requests.put(url=url, data=json.dumps(temp_forward_data), headers=headers,
                                                       timeout=self.time_out, verify=self.verify_cert)
                            ep_response_json = ep_response.json()
                            if ep_response_json.get('endpoints'):
                                cur_ep = ep_response_json.get('endpoints')[0]
                                cur_trid = cur_ep.get('trid')
                                cur_state = self._wait_for_trid(str(cur_trid))
                                if cur_state:
                                    ep_state = True
                                    break
                        except requests.exceptions.RequestException:
                            pass
                    if not ep_state:
                        command_state_str = 'Failure'
                    ep['completion'] = ep_state
                    ep['instance_number'] = i if ep_state else None

        context = {
            'Rule': {
                'Name': rule_name,
                'Definition': rule,
                'RCS': rcs
            },
            'Status': {
                'command_state': command_state_str,
                'timestamp': response_timestamp
            },
            'Endpoints': endpoints
        }

        return context

    """SOAR API"""
    def block_conversation(self, src_ip: str, target_ip: str, rule_name: str, src_port: str = None,
                           target_port: str = None, protocol: str = None, rcs: str = None) -> dict:
        """ Creates a rule that drops all packets matching the specified 5-tuple values.

        Args:
            src_ip: The source IP address.
            target_ip: The destination IP address.
            rule_name: The name of the rule to create.
            src_port: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            target_port: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            protocol: The protocol (e.g., TCP) used for the packets.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        src_ip = self._process_ip_address(src_ip)

        src_port = self._process_port_range(src_port)

        target_ip = self._process_ip_address(target_ip)

        target_port = self._process_port_range(target_port)

        if not protocol:
            protocol = 'HOPOPT-255'  # default protocol is no value provided

        protocol = protocol.upper()

        rule = f'{target_ip} @ {target_port} & {src_ip} @ {src_port} <> {protocol} : DROP, END'

        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='5-tuple', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)

        return self._do_request(data, rule_name, rule, rcs)

    def unblock_conversation(self, rule_name: str, rcs: str = None) -> dict:
        """ Deletes a named rule from the 5-tuple logic block.

            This allows the previously blocked conversation to resume.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='5-tuple', instance_id=None, rcs=rcs)

    def record_conversation(self, src_ip: str, target_ip: str, vlan_id: str, rule_name: str, src_port: str = None,
                            target_port: str = None, protocol: str = None, sia_interface: str = None,
                            transport_type: str = None, tti_index: str = None, aio_index: str = None,
                            trigger_type: str = None, trigger_value: str = None, rcs: str = None) -> dict:
        """ Creates a rule that redirects a conversation matching 5-tuple values
            to the Packet Recorder and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            src_ip: The source IP address.
            target_ip: The destination IP address.
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            src_port: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            target_port: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            protocol: The protocol (e.g., TCP) used for the packets.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.
        """
        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        src_ip = self._process_ip_address(src_ip)

        src_port = self._process_port_range(src_port)

        target_ip = self._process_ip_address(target_ip)

        target_port = self._process_port_range(target_port)

        if not protocol:
            protocol = 'HOPOPT-255'

        protocol = protocol.upper()

        rule = f'{target_ip} @ {target_port} & {src_ip} @ {src_port} <> {protocol} : ' \
            f'REDIRECT-VLAN {sia_interface} {vlan_id}'
        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value to '
                                     f'use {transport_type} to send an alert.')

            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                                  trigger_type, int(trigger_value))

        rule += ', END'

        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='5-tuple', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def stop_recording_conversation(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes the named rule from the 5-tuple block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='5-tuple', instance_id=None, rcs=rcs)

    def alert_conversation(self, src_ip: str, target_ip: str, rule_name: str, transport_type: str, tti_index: str,
                           aio_index: str, trigger_type: str, trigger_value: str, src_port: str = None,
                           target_port: str = None, protocol: str = None, rcs: str = None) -> dict:
        """ Adds a rule that generates an alert when a conversation matching the specified 5-tuple values is detected.

        Args:
            src_ip: The source IP address.
            target_ip: The destination IP address.
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            src_port: The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”),
                or a combination (e.g., “1, 3-5”).
            target_port: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            protocol: The protocol (e.g., TCP) used for the packets.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        src_ip = self._process_ip_address(src_ip)

        src_port = self._process_port_range(src_port)

        target_ip = self._process_ip_address(target_ip)

        target_port = self._process_port_range(target_port)

        if not protocol:
            protocol = 'HOPOPT-255'  # default protocol

        protocol = protocol.upper()

        rule = f'{target_ip} @ {target_port} & {src_ip} @ {src_port} <> {protocol} : '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                              trigger_type, int(trigger_value)) + ', END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='5-tuple', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)

        return self._do_request(data, rule_name, rule, rcs)

    def mute_alert_conversation(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the 5-tuple logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='5-tuple', instance_id=None, rcs=rcs)

    def block_dest_port(self, port_range: str, rule_name: str, rcs: str) -> dict:
        """ Creates a rule that blocks packets destined for one or more specific ports.

        Args:
            port_range: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            rule_name: The name of the rule to create.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_port_range(port_range)}: DROP, END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='dst-port', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def unblock_dest_port(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the destination port logic block.

            This allows the previously blocked traffic to resume.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='dst-port', instance_id=None, rcs=rcs)

    def record_dest_port(self, port_range: str, vlan_id: str, rule_name: str, sia_interface: str = None,
                         transport_type: str = None, tti_index: str = None, aio_index: str = None,
                         trigger_type: str = None, trigger_value: str = None, rcs: str = None) -> dict:
        """ Adds a rule that redirects traffic destined for one or more ports to the Packet Recorder
            and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            port_range: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.
        """
        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        rule = f'{self._process_port_range(port_range)}: REDIRECT-VLAN {sia_interface} {vlan_id}'

        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value '
                                     f'to use {transport_type} to send an alert.')

            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                                  trigger_type, int(trigger_value))
        rule += ', END'

        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='dst-port', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def stop_recording_dest_port(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the destination port logic block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """

        return self._remove_rule(rule_name=rule_name, logic_block='dst-port', instance_id=None, rcs=rcs)

    def alert_dest_port(self, port_range: str, rule_name: str, transport_type: str, tti_index: str, aio_index: str,
                        trigger_type: str, trigger_value: str, rcs: str = None) -> dict:
        """ Creates a rule that generates an alert when traffic destined for one or more ports is detected.

        Args:
            port_range: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_port_range(port_range)}: '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index), trigger_type,
                                              int(trigger_value)) + ', END'

        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='dst-port', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def mute_alert_dest_port(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the destination port logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='dst-port', instance_id=None, rcs=rcs)

    def block_src_port(self, port_range: str, rule_name: str, rcs: str = None) -> dict:
        """ Adds a rule that blocks packets originating from one or more specific ports.

        Args:
            port_range: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            rule_name: The name of the rule to create.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_port_range(port_range)}: DROP, END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='src-port', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def unblock_src_port(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the source port logic block.

            This allows the previously blocked traffic to resume.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='src-port', instance_id=None, rcs=rcs)

    def record_src_port(self, port_range: str, vlan_id: str, rule_name: str, sia_interface: str = None,
                        transport_type: str = None, tti_index: str = None, aio_index: str = None,
                        trigger_type: str = None, trigger_value: str = None, rcs: str = None) -> dict:
        """ Adds a rule that redirects traffic originating from one or more ports to
            the Packet Recorder and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            port_range: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.

        """
        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        rule = f'{self._process_port_range(port_range)}: REDIRECT-VLAN {sia_interface} {vlan_id}'

        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value '
                                     f'to use {transport_type} to send an alert.')

            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index), trigger_type,
                                                  int(trigger_value))

        rule += ', END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='src-port', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def stop_recording_src_port(self, rule_name: str, rcs: str = None):
        """ Removes a named rule from the source port logic block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """

        return self._remove_rule(rule_name=rule_name, logic_block='src-port', instance_id=None, rcs=rcs)

    def alert_src_port(self, port_range: str, rule_name: str, transport_type: str, tti_index: str, aio_index: str,
                       trigger_type: str, trigger_value: str, rcs: str = None) -> dict:
        """ Creates a rule that generates an alert when traffic originating from one or more ports is detected.

        Args:
            port_range: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_port_range(port_range)}: '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                              trigger_type, int(trigger_value)) + ', END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='src-port', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def mute_alert_src_port(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the source port logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='src-port', instance_id=None, rcs=rcs)

    def block_dest_subnet(self, target_ip: str, rule_name: str, rcs: str = None) -> dict:
        """ Adds a rule that blocks packets destined for a specific IP address or range of IP addresses.

        Args:
            target_ip: The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            rule_name: The name of the rule to create.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_ip_address(target_ip)}: DROP, END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='dst-subnet', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def unblock_dest_subnet(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the destination subnet logic block.

            This allows the previously blocked traffic to resume.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='dst-subnet', instance_id=None, rcs=rcs)

    def record_dest_subnet(self, target_ip: str, vlan_id: str, rule_name: str, sia_interface: str = None,
                           transport_type: str = None, tti_index: str = None, aio_index: str = None,
                           trigger_type: str = None, trigger_value: str = None, rcs: str = None) -> dict:
        """ Creates a rule that redirects traffic destined for a specific IP address or
            range of IP addresses to the Packet Recorder and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            target_ip: The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.

        """

        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        rule = f'{self._process_ip_address(target_ip)}: REDIRECT-VLAN {sia_interface} {vlan_id}'

        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value '
                                     f'to use {transport_type} to send an alert.')

            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                                  trigger_type, int(trigger_value))
        rule += ', END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='dst-subnet', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def stop_recording_dest_subnet(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the destination subnet logic block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """

        return self._remove_rule(rule_name=rule_name, logic_block='dst-subnet', instance_id=None, rcs=rcs)

    def alert_dest_subnet(self, target_ip: str, rule_name: str, transport_type: str, tti_index: str, aio_index: str,
                          trigger_type: str, trigger_value: str, rcs: str = None) -> dict:
        """ Creates a rule that generates an alert when traffic destined for
            a specific IP address or range of IP addresses is detected.

        Args:
            target_ip: The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_ip_address(target_ip)}: '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index), trigger_type,
                                              int(trigger_value)) + ', END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='dst-subnet', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def mute_alert_dest_subnet(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the destination subnet logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='dst-subnet', instance_id=None, rcs=rcs)

    def block_src_subnet(self, src_ip: str, rule_name: str, rcs: str = None) -> dict:
        """ Adds a rule that blocks packets originating from a specific IP address or range of IP addresses.

        Args:
            src_ip: The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            rule_name: The name of the rule to create.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_ip_address(src_ip)}: DROP, END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='src-subnet', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def unblock_src_subnet(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the source subnet logic block.

            This allows the previously blocked traffic to resume.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='src-subnet', instance_id=None, rcs=rcs)

    def record_src_subnet(self, src_ip: str, vlan_id: str, rule_name: str, sia_interface: str = None,
                          transport_type: str = None, tti_index: str = None, aio_index: str = None,
                          trigger_type: str = None, trigger_value: str = None, rcs: str = None) -> dict:
        """ Creates a rule that redirects traffic originating from one or more specific IP addresses
            to the Packet Recorder and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            src_ip: The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.

        """

        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        rule = f'{self._process_ip_address(src_ip)}: REDIRECT-VLAN {sia_interface} {vlan_id}'

        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value '
                                     f'to use {transport_type} to send an alert.')
            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                                  trigger_type, int(trigger_value))

        rule += ', END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='src-subnet', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)

        return self._do_request(data, rule_name, rule, rcs)

    def stop_recording_src_subnet(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the source subnet logic block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='src-subnet', instance_id=None, rcs=rcs)

    def alert_src_subnet(self, src_ip: str, rule_name: str, transport_type: str, tti_index: str, aio_index: str,
                         trigger_type: str, trigger_value: str, rcs: str = None) -> dict:
        """ Adds a rule that generates an alert when traffic originating from a specific IP address
            or range of IP addresses is detected.

        Args:
            src_ip: The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_ip_address(src_ip)}: '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                              trigger_type, int(trigger_value)) + ', END'
        sd_list, sia_list = self._parse_rcs(rcs)
        data = self._generate_rule_forward_spec(rule_name=rule_name, logic_block='src-subnet', rule=rule,
                                                named_rule_action='add', sd_list=sd_list, sia_list=sia_list)
        return self._do_request(data, rule_name, rule, rcs)

    def mute_alert_src_subnet(self, rule_name: str, rcs: str = None) -> dict:
        """ Removes a named rule from the source subnet logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            rcs: Remediation Configuration String.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name=rule_name, logic_block='src-subnet', instance_id=None, rcs=rcs)


''' HELPER FUNCTIONS '''


def func_call(instance: ARIA, func_name: str, command_name: str, demisto_arguments: list, args: dict):
    """ Helper function used to call different demisto command

    Args:
        instance: An ARIA instance.
        func_name: Name of the functions in the ARIA class.
        command_name: Related demisto command name.
        demisto_arguments: List of arguments name in the right order.
        args: Input of demisto arguments dict.

    """
    arguments_value = []
    for arg in demisto_arguments:
        value = args.get(arg)  # get values from demisto command
        arguments_value.append(value)

    context_entry = getattr(instance, func_name)(*tuple(arguments_value))  # get returned tuple

    table_header = ['Rule', 'Status', 'Endpoints']

    context_name = func_name.title().replace('_', '')

    ec = {
        f'Aria.{context_name}(val.name && val.name == obj.name)': context_entry
    }

    readable_output = tableToMarkdown(command_name, context_entry, table_header)

    return readable_output, ec


''' COMMAND FUNCTION '''


def block_conversation_command(instance, args):
    demisto_arguments = ['src_ip', 'target_ip', 'rule_name', 'src_port', 'target_port', 'protocol', 'rcs']
    return func_call(instance, 'block_conversation', 'aria-block-conversation', demisto_arguments, args)


def unblock_conversation_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'unblock_conversation', 'aria-unblock-conversation', demisto_arguments, args)


def record_conversation_command(instance, args):
    demisto_arguments = ['src_ip', 'target_ip', 'vlan_id', 'rule_name', 'src_port', 'target_port', 'protocol',
                         'sia_interface', 'transport_type', 'tti_index', 'aio_index', 'trigger_type', 'trigger_value', 'rcs']
    return func_call(instance, 'record_conversation', 'aria-record-conversation', demisto_arguments, args)


def stop_recording_conversation_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'stop_recording_conversation', 'aria-stop-recording-conversation',
                     demisto_arguments, args)


def alert_conversation_command(instance, args):
    demisto_arguments = ['src_ip', 'target_ip', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'src_port', 'target_port', 'protocol', 'rcs']
    return func_call(instance, 'alert_conversation', 'aria-alert-conversation', demisto_arguments, args)


def mute_alert_conversation_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'mute_alert_conversation', 'aria-mute-alert-conversation', demisto_arguments, args)


def block_dest_port_command(instance, args):
    demisto_arguments = ['port_range', 'rule_name', 'rcs']
    return func_call(instance, 'block_dest_port', 'aria-block-dest-port', demisto_arguments, args)


def unblock_dest_port_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'unblock_dest_port', 'aria-unblock-dest-port', demisto_arguments, args)


def record_dest_port_command(instance, args):
    demisto_arguments = ['port_range', 'vlan_id', 'rule_name', 'sia_interface', 'transport_type', 'tti_index',
                         'aio_index', 'trigger_type', 'trigger_value', 'rcs']
    return func_call(instance, 'record_dest_port', 'aria-record-dest-port', demisto_arguments, args)


def stop_recording_dest_port_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'stop_recording_dest_port', 'aria-stop-recording-dest-port', demisto_arguments, args)


def alert_dest_port_command(instance, args):
    demisto_arguments = ['port_range', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'rcs']
    return func_call(instance, 'alert_dest_port', 'aria-alert-dest-port', demisto_arguments, args)


def mute_alert_dest_port_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'mute_alert_dest_port', 'aria-mute-alert-dest-port', demisto_arguments, args)


def block_src_port_command(instance, args):
    demisto_arguments = ['port_range', 'rule_name', 'rcs']
    return func_call(instance, 'block_src_port', 'aria-block-src-port', demisto_arguments, args)


def unblock_src_port_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'unblock_src_port', 'aria-unblock-src-port', demisto_arguments, args)


def record_src_port_command(instance, args):
    demisto_arguments = ['port_range', 'vlan_id', 'rule_name', 'sia_interface', 'transport_type', 'tti_index',
                         'aio_index', 'trigger_type', 'trigger_value', 'rcs']
    return func_call(instance, 'record_src_port', 'aria-record-src-port', demisto_arguments, args)


def stop_recording_src_port_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'stop_recording_src_port', 'aria-stop-recording-src-port', demisto_arguments, args)


def alert_src_port_command(instance, args):
    demisto_arguments = ['port_range', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'rcs']
    return func_call(instance, 'alert_src_port', 'aria-alert-src-port', demisto_arguments, args)


def mute_alert_src_port_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'mute_alert_src_port', 'aria-mute-alert-src-port', demisto_arguments, args)


def block_dest_subnet_command(instance, args):
    demisto_arguments = ['target_ip', 'rule_name', 'rcs']
    return func_call(instance, 'block_dest_subnet', 'aria-block-dest-subnet', demisto_arguments, args)


def unblock_dest_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'unblock_dest_subnet', 'aria-unblock-dest-subnet', demisto_arguments, args)


def record_dest_subnet_command(instance, args):
    demisto_arguments = ['target_ip', 'vlan_id', 'rule_name', 'sia_interface', 'transport_type', 'tti_index',
                         'aio_index', 'trigger_type', 'trigger_value', 'rcs']
    return func_call(instance, 'record_dest_subnet', 'aria-record-dest-subnet', demisto_arguments, args)


def stop_recording_dest_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'stop_recording_dest_subnet', 'aria-stop-recording-dest-subnet',
                     demisto_arguments, args)


def alert_dest_subnet_command(instance, args):
    demisto_arguments = ['target_ip', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'rcs']
    return func_call(instance, 'alert_dest_subnet', 'aria-alert-dest-subnet', demisto_arguments, args)


def mute_alert_dest_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'mute_alert_dest_subnet', 'aria-mute-alert-dest-subnet', demisto_arguments, args)


def block_src_subnet_command(instance, args):
    demisto_arguments = ['src_ip', 'rule_name', 'rcs']
    return func_call(instance, 'block_src_subnet', 'aria-block-src-subnet', demisto_arguments, args)


def unblock_src_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'unblock_src_subnet', 'aria-unblock-src-subnet', demisto_arguments, args)


def record_src_subnet_command(instance, args):
    demisto_arguments = ['src_ip', 'vlan_id', 'rule_name', 'sia_interface', 'transport_type', 'tti_index', 'aio_index',
                         'trigger_type', 'trigger_value', 'rcs']
    return func_call(instance, 'record_src_subnet', 'aria-record-src-subnet', demisto_arguments, args)


def stop_recording_src_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'stop_recording_src_subnet', 'aria-stop-recording-src-subnet', demisto_arguments, args)


def alert_src_subnet_command(instance, args):
    demisto_arguments = ['src_ip', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'rcs']
    return func_call(instance, 'alert_src_subnet', 'aria-alert-src-subnet', demisto_arguments, args)


def mute_alert_src_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'rcs']
    return func_call(instance, 'mute_alert_src_subnet', 'aria-mute-alert-src-subnet', demisto_arguments, args)


def main():
    # disable insecure warnings
    requests.packages.urllib3.disable_warnings()

    # IP address or FQDN of your SDSo node
    SDSO = demisto.params().get('sdso')

    handle_proxy()

    INSECURE = demisto.params().get('insecure', False)

    verify_cert = not INSECURE

    sdso_url = f'{SDSO}/Aria/SS/1.0.0/PacketIntelligence/server'

    aria = ARIA(sdso_url, verify_cert)

    commnds_dict = {
        'aria-block-conversation': block_conversation_command,
        'aria-unblock-conversation': unblock_conversation_command,
        'aria-record-conversation': record_conversation_command,
        'aria-stop-recording-conversation': stop_recording_conversation_command,
        'aria-alert-conversation': alert_conversation_command,
        'aria-mute-alert-conversation': mute_alert_conversation_command,
        'aria-block-dest-port': block_dest_port_command,
        'aria-unblock-dest-port': unblock_dest_port_command,
        'aria-record-dest-port': record_dest_port_command,
        'aria-stop-recording-dest-port': stop_recording_dest_port_command,
        'aria-alert-dest-port': alert_dest_port_command,
        'aria-mute-alert-dest-port': mute_alert_dest_port_command,
        'aria-block-src-port': block_src_port_command,
        'aria-unblock-src-port': unblock_src_port_command,
        'aria-record-src-port': record_src_port_command,
        'aria-stop-recording-src-port': stop_recording_src_port_command,
        'aria-alert-src-port': alert_src_port_command,
        'aria-mute-alert-src-port': mute_alert_src_port_command,
        'aria-block-dest-subnet': block_dest_subnet_command,
        'aria-unblock-dest-subnet': unblock_dest_subnet_command,
        'aria-record-dest-subnet': record_dest_subnet_command,
        'aria-stop-recording-dest-subnet': stop_recording_dest_subnet_command,
        'aria-alert-dest-subnet': alert_dest_subnet_command,
        'aria-mute-alert-dest-subnet': mute_alert_dest_subnet_command,
        'aria-block-src-subnet': block_src_subnet_command,
        'aria-unblock-src-subnet': unblock_src_subnet_command,
        'aria-record-src-subnet': record_src_subnet_command,
        'aria-stop-recording-src-subnet': stop_recording_src_subnet_command,
        'aria-alert-src-subnet': alert_src_subnet_command,
        'aria-mute-alert-src-subnet': mute_alert_src_subnet_command
    }

    command = demisto.command()
    LOG('ARIA: command is %s' % (command,))

    if demisto.command() == 'test-module':
        # Test if the ARIA PI Reaper is ready
        url = sdso_url + '/endPoint'
        try:
            res = requests.get(url, timeout=20, verify=verify_cert)
            size = len(json.loads(res.text))
            if res.ok and size != 0:
                demisto.results('ok')
            else:
                return_error('Fail to Connect to SDSo or no PacketIntelligence Service!')
        except (json.JSONDecodeError, requests.exceptions.RequestException):
            return_error('Fail to Connect to SDSo or no PacketIntelligence Service!')

    else:
        cmd_func = commnds_dict.get(command)

        if cmd_func is None:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
        else:
            readable_output, ec = cmd_func(aria, demisto.args())
            context_entry = list(ec.values())[0]

            LOG(json.dumps(ec))

            if context_entry['Status']['command_state'] == 'Success':
                return_outputs(readable_output, ec)
            elif context_entry['Status']['command_state'] == 'Failure':
                LOG.print_log()
                return_error(f'One or more endpoint(s) fail to create/remove rules. Please see {context_entry}')
            else:
                return_error(f'Endpoint matching RCS not found! Please see {context_entry}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
