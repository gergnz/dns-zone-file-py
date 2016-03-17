#!/usr/bin/python 

import copy
import datetime
import time
import argparse
from collections import defaultdict

SUPPORTED_RECORDS = ['$ORIGIN', '$TTL', 'SOA', 'NS', 'A', 'AAAA', 'CNAME', 'MX', 'PTR', 'TXT', 'SRV', 'SPF', 'URI']

"""
Known limitations:
    * only one $ORIGIN and one $TTL are supported
    * only the IN class is supported
    * PTR records must have a non-empty name
    * currently only supports: '$ORIGIN', '$TTL', 'SOA', 'NS', 'A', 'AAAA', 'CNAME', 'MX', 'PTR', 'TXT', 'SRV', 'SPF', 'URI'
"""

defaultTemplate = """
{$origin}\n\
{$ttl}\n\
\n\
{soa}
\n\
{ns}\n\
\n\
{mx}\n\
\n\
{a}\n\
\n\
{aaaa}\n\
\n\
{cname}\n\
\n\
{ptr}\n\
\n\
{txt}\n\
\n\
{srv}\n\
\n\
{spf}\n\
\n\
{uri}\n\
"""

class InvalidLineException(Exception):
    pass

class ZonefileLineParser( argparse.ArgumentParser ):

    def error(self, message):
        """
        Silent error message
        """
        raise InvalidLineException(message)


def generate( options, template=None ):
    """
    Generate the DNS zonefile, given a dict-encoded
    description of the zonefile (@options) and the
    template to fill in (@template)
    """

    global defaultTemplate
    if template is None:
        template = defaultTemplate[:]

    template = process_ORIGIN( options.get('$ORIGIN', None), template )
    template = process_TTL( options.get('$TTL', None), template )
    template = processSOA( options.get('SOA', None), template )
    template = processNS( options.get('NS', None), template )
    template = processA( options.get('A', None), template )
    template = processAAAA( options.get('AAAA', None), template )
    template = processCNAME( options.get('CNAME', None), template )
    template = processMX( options.get('MX', None), template )
    template = processPTR( options.get('PTR', None), template )
    template = processTXT( options.get('TXT', None), template )
    template = processSRV( options.get('SRV', None), template )
    template = processSPF( options.get('SPF', None), template )
    template = processURI( options.get('URI', None), template )

    # remove newlines, but terminate with one
    template = "\n".join( filter( lambda l: len(l.strip()) > 0, [tl.strip() for tl in template.split("\n")]) ) + "\n"
    return template


def process_ORIGIN( data, template ):
    """
    Replace {$origin} in template with a serialized $ORIGIN record
    """
    ret = ""
    if data is not None:
        ret += "$ORIGIN %s" % data

    return template.replace("{$origin}", ret)


def process_TTL( data, template ):
    """
    Replace {$ttl} in template with a serialized $TTL record
    """
    ret = ""
    if data is not None:
        ret += "$TTL %s" % data

    return template.replace("{$ttl}", ret)


def processSOA( data, template ):
    """
    Replace {SOA} in template with a set of serialized SOA records
    """
    ret = template[:]

    if data is not None:
    
        assert len(data) == 1, "Only support one SOA RR at this time"
        data = data[0]

        soadat = []
        domain_fields = ['mname', 'rname']
        param_fields = ['serial', 'refresh', 'retry', 'expire', 'minimum']

        for f in domain_fields + param_fields:
            assert f in data.keys(), "Missing '%s' (%s)" % (f, data)

        data_name = str(data.get('name', '@'))
        soadat.append(data_name)

        if data.get('ttl') is not None:
            soadat.append( str(data['ttl']) )
  
        soadat.append("IN")
        soadat.append("SOA")

        for key in domain_fields:
            value = str(data[key])
            soadat.append( value )

        soadat.append("(")

        for key in param_fields:
            value = str(data[key])
            soadat.append( value )

        soadat.append(")")

        soa_txt = " ".join(soadat)
        ret = ret.replace("{soa}", soa_txt)

    else:
        # clear all SOA fields 
        ret = ret.replace("{soa}", "")

    return ret


def quoteField( data, field ):
    """
    Quote a field in a list of DNS records.
    Return the new data records.
    """
    if data is None:
        return None 

    data_dup = copy.deepcopy(data)
    for i in xrange(0, len(data_dup)):
        data_dup[i][field] = '"%s"' % data_dup[i][field]
        data_dup[i][field] = data_dup[i][field].replace(";", "\;")

    return data_dup


def processRR( data, rectype, reckey, field, template ):
    """
    Meta method:
    Replace $field in template with the serialized $rectype records,
    using @reckey from each datum.
    """
    if data is None:
        return template.replace(field, "")

    if type(reckey) != list:
        reckey = [reckey]

    assert type(data) == list, "Data must be a list"

    ret = ""
    for i in xrange(0, len(data)):

        for rk in reckey:
            assert rk in data[i].keys(), "Missing '%s'" % rk

        retdat = []
        retdat.append( str(data[i].get('name', '@')) )
        if data[i].get('ttl') is not None:
            retdat.append( str(data[i]['ttl']) )

        retdat.append(rectype)
        retdat += [str(data[i][rk]) for rk in reckey]
        ret += " ".join(retdat) + "\n"

    return template.replace(field, ret)


def processNS( data, template ):
    """
    Replace {ns} in template with the serialized NS records
    """
    return processRR( data, "NS", "host", "{ns}", template )


def processA( data, template ):
    """
    Replace {a} in template with the serialized A records
    """
    return processRR( data, "A", "ip", "{a}", template)


def processAAAA( data, template ):
    """
    Replace {aaaa} in template with the serialized A records
    """
    return processRR( data, "AAAA", "ip", "{aaaa}", template )


def processCNAME( data, template ):
    """
    Replace {cname} in template with the serialized CNAME records
    """
    return processRR( data, "CNAME", "alias", "{cname}", template )


def processMX( data, template ):
    """
    Replace {mx} in template with the serialized MX records
    """
    return processRR( data, "MX", ["preference", "host"], "{mx}", template)


def processPTR( data, template ):
    """
    Replace {ptr} in template with the serialized PTR records
    """
    return processRR( data, "PTR", "host", "{ptr}", template)


def processTXT( data, template ):
    """
    Replace {txt} in template with the serialized TXT records
    """
    # quote txt
    data_dup = quoteField( data, "txt" )
    return processRR( data_dup, "TXT", "txt", "{txt}", template)


def processSRV( data, template ):
    """
    Replace {srv} in template with the serialized SRV records
    """
    return processRR( data, "SRV", ["priority", "weight", "port", "target"], "{srv}", template )


def processSPF( data, template ):
    """
    Replace {spf} in template with the serialized SPF records
    """
    return processRR( data, "SPF", "data", "{spf}", template)


def processURI( data, template ):
    """
    Replace {uri} in templtae with the serialized URI records
    """
    # quote target 
    data_dup = quoteField( data, "target" )
    return processRR( data_dup, "URI", ["priority", "weight", "target"], "{uri}", template )


def make_RR_subparser( subp, rec_type, args_and_types ):
    """
    Make a subparser for a given type of DNS record
    """
    sp = subp.add_parser(rec_type)

    sp.add_argument("name", type=str)
    sp.add_argument("ttl", type=int, nargs='?')
    sp.add_argument(rec_type, type=str)

    for (argname, argtype) in args_and_types:
        sp.add_argument( argname, type=argtype )

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
    make_RR_subparser( subp, "SOA", [("mname", str), \
                                     ("rname", str), \
                                     ("serial", int), \
                                     ("refresh", int), \
                                     ("retry", int), \
                                     ("expire", int), \
                                     ("minimum", int)] )

    make_RR_subparser( subp, "NS", [("host", str)] )
    make_RR_subparser( subp, "A", [("ip", str)] )
    make_RR_subparser( subp, "AAAA", [("ip", str)])
    make_RR_subparser( subp, "CNAME", [("alias", str)])
    make_RR_subparser( subp, "MX", [("preference", str), ("host", str)])
    make_RR_subparser( subp, "TXT", [("txt", str)] )
    make_RR_subparser( subp, "PTR", [("host", str)] )
    make_RR_subparser( subp, "SRV", [("priority", int), ("weight", int), ("port", int), ("target", str)] )
    make_RR_subparser( subp, "SPF", [("data", str)] )
    make_RR_subparser( subp, "URI", [("priority", int), ("weight", int), ("target", str)] )

    return p


def tokenize( line ):
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


def serialize( tokens ):
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


def remove_comments( text ):
    """
    Remove comments from a zonefile
    """
    ret = []
    lines = text.split("\n")
    for line in lines:
        if len(line) == 0:
            continue 

        line = serialize( tokenize( line ) )
        ret.append(line)

    return "\n".join(ret)


def flatten( text ):
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
        tokens += filter( lambda x: len(x) > 0, l.split(" ") ) + ['']

    # find (...) and turn it into a single line ("capture" it)
    capturing = False
    captured = []

    flattened = []
    while len(tokens) > 0:
        tok = tokens.pop(0)
        if not capturing and len(tok) == 0:
            # normal end-of-line
            if len(captured) > 0:
                flattened.append( " ".join(captured) )
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

    return "\n".join( flattened )


def remove_class( text ):
    """
    Remove the CLASS from each DNS record, if present.
    The only class that gets used today (for all intents
    and purposes) is 'IN'.
    """

    # see RFC 1035 for list of classes
    lines = text.split("\n")
    ret = []
    for line in lines:
        tokens = tokenize( line )
        tokens_upper = [t.upper() for t in tokens]

        if "IN" in tokens_upper:
            tokens.remove("IN")
        elif "CS" in tokens_upper:
            tokens.remove("CS")
        elif "CH" in tokens_upper:
            tokens.remove("CH")
        elif "HS" in tokens_upper:
            tokens.remove("HS")

        ret.append( serialize(tokens) )

    return "\n".join(ret)


def add_default_name( text ):
    """
    Go through each line of the text and ensure that 
    a name is defined.  Use '@' if there is none.
    """
    global SUPPORTED_RECORDS

    lines = text.split("\n")
    ret = []
    for line in lines:
        tokens = tokenize( line )
        if tokens[0] in SUPPORTED_RECORDS and not tokens[0].startswith("$"):
            # add back the name
            tokens = ['@'] + tokens 

        ret.append( serialize(tokens) )

    return "\n".join(ret)


def parse_zone_file( text, ignore_invalid=False ):
    """
    Parse a zonefile into a dict
    """
    # print "======== before"
    # print text
    text = remove_comments( text )
    # print "======== no comments"
    # print text
    text = flatten( text )
    # print "======== flattened"
    # print text
    text = remove_class( text )
    # print "======== no class"
    # print text
    text = add_default_name( text )
    # print "======== default name"
    # print text
    return parse_lines( text, ignore_invalid=ignore_invalid )


def parse_line( parser, RRtok, parsed_records ):
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
        rr, unmatched = parser.parse_known_args( RRtok )
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
            parsed_records[rectype].append( rrd )


    return parsed_records


def parse_lines( text, ignore_invalid=False ):
    """
    Parse a zonefile into a dict.
    @text must be flattened--each record must be on one line.
    Also, all comments must be removed.
    """
    ret = defaultdict(list)
    rrs = text.split("\n")
    parser = make_parser()

    for rrtxt in rrs:
        RRtok = tokenize( rrtxt )
        try:
            ret = parse_line( parser, RRtok, ret )
        except InvalidLineException:
            if ignore_invalid:
                continue
            else:
                raise

    return ret


def make_zone_file( zonefile_data, origin=None, ttl=None ):
    """
    Given zonefile data, export it to an actual zonefile.
    zonefile_data = {
        "$ORIGIN": origin server,
        "$TTL": default time-to-live,
        "SOA": [ soa records ],
        "NS": [ ns records ],
        "A": [ a records ],
        "AAAA": [ aaaa records ]
        "CNAME": [ cname records ]
        "MX": [ mx records ]
        "PTR": [ ptr records ]
        "TXT": [ txt records ]
        "SRV": [ srv records ]
        "SPF": [ spf records ]
        "URI": [ uri records ]
    }
    """
    if origin is not None:
        zonefile_data['$ORIGIN'] = origin 

    if ttl is not None:
        zonefile_data['$TTL'] = ttl

    return generate( zonefile_data )


