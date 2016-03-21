#!/usr/bin/python 

"""
Known limitations:
    * only one $ORIGIN and one $TTL are supported
    * only the IN class is supported
    * PTR records must have a non-empty name
    * currently only supports the following:
    '$ORIGIN', '$TTL', 'SOA', 'NS', 'A', 'AAAA', 'CNAME', 'MX', 'PTR',
    'TXT', 'SRV', 'SPF', 'URI'
"""

import copy
import datetime
import time
import argparse
from collections import defaultdict

from .configs import SUPPORTED_RECORDS, DEFAULT_TEMPLATE
from .exceptions import InvalidLineException


class ZonefileLineParser(argparse.ArgumentParser):
    def error(self, message):
        """
        Silent error message
        """
        raise InvalidLineException(message)


def make_rr_subparser(subp, rec_type, args_and_types):
    """
    Make a subparser for a given type of DNS record
    """
    sp = subp.add_parser(rec_type)

    sp.add_argument("name", type=str)
    sp.add_argument("ttl", type=int, nargs='?')
    sp.add_argument(rec_type, type=str)

    for (argname, argtype) in args_and_types:
        sp.add_argument(argname, type=argtype)

    return sp


def make_parser():
    """
    Make an ArgumentParser that accepts DNS RRs
    """
    p = ZonefileLineParser()
    subp = p.add_subparsers()

    # parse $ORIGIN
    sp = subp.add_parser("$ORIGIN")
    sp.add_argument("$ORIGIN", type=str)

    # parse $TTL
    sp = subp.add_parser("$TTL")
    sp.add_argument("$TTL", type=int)

    # parse each RR
    args_and_types = [
        ("mname", str), ("rname", str), ("serial", int), ("refresh", int),
        ("retry", int), ("expire", int), ("minimum", int)
    ]
    make_rr_subparser(subp, "SOA", args_and_types)

    make_rr_subparser(subp, "NS", [("host", str)])
    make_rr_subparser(subp, "A", [("ip", str)])
    make_rr_subparser(subp, "AAAA", [("ip", str)])
    make_rr_subparser(subp, "CNAME", [("alias", str)])
    make_rr_subparser(subp, "MX", [("preference", str), ("host", str)])
    make_rr_subparser(subp, "TXT", [("txt", str)])
    make_rr_subparser(subp, "PTR", [("host", str)])
    make_rr_subparser(subp, "SRV", [("priority", int), ("weight", int), ("port", int), ("target", str)])
    make_rr_subparser(subp, "SPF", [("data", str)])
    make_rr_subparser(subp, "URI", [("priority", int), ("weight", int), ("target", str)])

    return p


def tokenize(line):
    """
    Tokenize a line:
    * split tokens on whitespace
    * treat quoted strings as a single token
    * drop comments
    * handle escaped spaces and comment delimiters
    """
    ret = []
    escape = False
    quote = False
    tokbuf = ""
    ll = list(line)
    while len(ll) > 0:
        c = ll.pop(0)
        if c.isspace():
            if not quote and not escape:
                # end of token
                if len(tokbuf) > 0:
                    ret.append(tokbuf)

                tokbuf = ""

            elif quote:
                # in quotes
                tokbuf += c

            elif escape:
                # escaped space
                tokbuf += c
                escape = False

            else:
                tokbuf = ""

            continue

        if c == '\\':
            escape = True
            continue

        elif c == '"':
            if not escape:
                if quote:
                    # end of quote
                    ret.append(tokbuf)
                    tokbuf = ""
                    quote = False
                    continue

                else:
                    # beginning of quote
                    quote = True
                    continue

        elif c == ';':
            if not escape:
                # comment 
                ret.append(tokbuf)
                tokbuf = ""
                break
            
        # normal character
        tokbuf += c
        escape = False

    if len(tokbuf.strip(" ").strip("\n")) > 0:
        ret.append(tokbuf)

    return ret


def serialize(tokens):
    """
    Serialize tokens:
    * quote whitespace-containing tokens
    * escape semicolons
    """
    ret = []
    for tok in tokens:
        if " " in tok:
            tok = '"%s"' % tok

        if ";" in tok:
            tok = tok.replace(";", "\;")

        ret.append(tok)

    return " ".join(ret)


def remove_comments(text):
    """
    Remove comments from a zonefile
    """
    ret = []
    lines = text.split("\n")
    for line in lines:
        if len(line) == 0:
            continue 

        line = serialize(tokenize(line))
        ret.append(line)

    return "\n".join(ret)


def flatten(text):
    """
    Flatten the text:
    * make sure each record is on one line.
    * remove parenthesis 
    """
    lines = text.split("\n")

    # tokens: sequence of non-whitespace separated by '' where a newline was
    tokens = []
    for l in lines:
        if len(l) == 0:
            continue 

        l = l.replace("\t", " ")
        tokens += filter(lambda x: len(x) > 0, l.split(" ")) + ['']

    # find (...) and turn it into a single line ("capture" it)
    capturing = False
    captured = []

    flattened = []
    while len(tokens) > 0:
        tok = tokens.pop(0)
        if not capturing and len(tok) == 0:
            # normal end-of-line
            if len(captured) > 0:
                flattened.append(" ".join(captured))
                captured = []
            continue 

        if tok.startswith("("):
            # begin grouping
            tok = tok.lstrip("(")
            capturing = True

        if capturing and tok.endswith(")"):
            # end grouping.  next end-of-line will turn this sequence into a flat line
            tok = tok.rstrip(")")
            capturing = False 

        captured.append(tok)

    return "\n".join(flattened)


def remove_class(text):
    """
    Remove the CLASS from each DNS record, if present.
    The only class that gets used today (for all intents
    and purposes) is 'IN'.
    """

    # see RFC 1035 for list of classes
    lines = text.split("\n")
    ret = []
    for line in lines:
        tokens = tokenize(line)
        tokens_upper = [t.upper() for t in tokens]

        if "IN" in tokens_upper:
            tokens.remove("IN")
        elif "CS" in tokens_upper:
            tokens.remove("CS")
        elif "CH" in tokens_upper:
            tokens.remove("CH")
        elif "HS" in tokens_upper:
            tokens.remove("HS")

        ret.append(serialize(tokens))

    return "\n".join(ret)


def add_default_name(text):
    """
    Go through each line of the text and ensure that 
    a name is defined.  Use '@' if there is none.
    """
    global SUPPORTED_RECORDS

    lines = text.split("\n")
    ret = []
    for line in lines:
        tokens = tokenize(line)
        if len(tokens) == 0:
            continue

        if tokens[0] in SUPPORTED_RECORDS and not tokens[0].startswith("$"):
            # add back the name
            tokens = ['@'] + tokens 

        ret.append(serialize(tokens))

    return "\n".join(ret)


def parse_line(parser, RRtok, parsed_records):
    """
    Given the parser, capitalized list of a line's tokens, and the current set of records 
    parsed so far, parse it into a dictionary.

    Return the new set of parsed records.
    Raise an exception on error.
    """

    global SUPPORTED_RECORDS

    line = " ".join(RRtok)

    # match parser to record type
    if len(RRtok) >= 2 and RRtok[1] in SUPPORTED_RECORDS:
        # with no ttl
        RRtok = [RRtok[1]] + RRtok

    elif len(RRtok) >= 3 and RRtok[2] in SUPPORTED_RECORDS:
        # with ttl
        RRtok = [RRtok[2]] + RRtok

    try:
        rr, unmatched = parser.parse_known_args(RRtok)
        assert len(unmatched) == 0, "Unmatched fields: %s" % unmatched

    except (SystemExit, AssertionError, InvalidLineException):
        # invalid argument 
        raise InvalidLineException(line)

    rrd = rr.__dict__

    # what kind of record? including origin and ttl
    rectype = None
    for key in rrd.keys():
        if key in SUPPORTED_RECORDS and (key.startswith("$") or rrd[key] == key):
            rectype = key
            if rrd[key] == key:
                del rrd[key]
            break

    assert rectype is not None, "Unknown record type in %s" % rr

    # clean fields
    for field in rrd.keys():
        if rrd[field] is None:
            del rrd[field]

    current_origin = rrd.get('$ORIGIN', parsed_records.get('$ORIGIN', None))

    # special record-specific fix-ups
    if rectype == 'PTR':
        rrd['fullname'] = rrd['name'] + '.' + current_origin
      
    if len(rrd) > 0:
        if rectype.startswith("$"):
            # put the value directly
            parsed_records[rectype] = rrd[rectype]

        else:
            parsed_records[rectype].append(rrd)


    return parsed_records


def parse_lines(text, ignore_invalid=False):
    """
    Parse a zonefile into a dict.
    @text must be flattened--each record must be on one line.
    Also, all comments must be removed.
    """
    ret = defaultdict(list)
    rrs = text.split("\n")
    parser = make_parser()

    for rrtxt in rrs:
        RRtok = tokenize(rrtxt)
        try:
            ret = parse_line(parser, RRtok, ret)
        except InvalidLineException:
            if ignore_invalid:
                continue
            else:
                raise

    return ret


def parse_zone_file(text, ignore_invalid=False):
    """
    Parse a zonefile into a dict
    """
    text = remove_comments(text)
    text = flatten(text)
    text = remove_class(text)
    text = add_default_name(text)
    return parse_lines(text, ignore_invalid=ignore_invalid)
