import copy


def process_origin(data, template):
    """
    Replace {$origin} in template with a serialized $ORIGIN record
    """
    ret = ""
    if data is not None:
        ret += "$ORIGIN %s" % data

    return template.replace("{$origin}", ret)


def process_ttl(data, template):
    """
    Replace {$ttl} in template with a serialized $TTL record
    """
    ret = ""
    if data is not None:
        ret += "$TTL %s" % data

    return template.replace("{$ttl}", ret)


def process_soa(data, template):
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


def quote_field(data, field):
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


def process_rr(data, rectype, reckey, field, template):
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


def process_ns(data, template):
    """
    Replace {ns} in template with the serialized NS records
    """
    return process_rr(data, "NS", "host", "{ns}", template)


def process_a(data, template):
    """
    Replace {a} in template with the serialized A records
    """
    return process_rr(data, "A", "ip", "{a}", template)


def process_aaaa(data, template):
    """
    Replace {aaaa} in template with the serialized A records
    """
    return process_rr(data, "AAAA", "ip", "{aaaa}", template)


def process_cname(data, template):
    """
    Replace {cname} in template with the serialized CNAME records
    """
    return process_rr(data, "CNAME", "alias", "{cname}", template)


def process_mx(data, template):
    """
    Replace {mx} in template with the serialized MX records
    """
    return process_rr(data, "MX", ["preference", "host"], "{mx}", template)


def process_ptr(data, template):
    """
    Replace {ptr} in template with the serialized PTR records
    """
    return process_rr(data, "PTR", "host", "{ptr}", template)


def process_txt(data, template):
    """
    Replace {txt} in template with the serialized TXT records
    """
    # quote txt
    data_dup = quote_field(data, "txt")
    return process_rr(data_dup, "TXT", "txt", "{txt}", template)


def process_srv(data, template):
    """
    Replace {srv} in template with the serialized SRV records
    """
    return process_rr(data, "SRV", ["priority", "weight", "port", "target"], "{srv}", template)


def process_spf(data, template):
    """
    Replace {spf} in template with the serialized SPF records
    """
    return process_rr(data, "SPF", "data", "{spf}", template)


def process_uri(data, template):
    """
    Replace {uri} in templtae with the serialized URI records
    """
    # quote target 
    data_dup = quote_field(data, "target")
    return process_rr(data_dup, "URI", ["priority", "weight", "target"], "{uri}", template)
