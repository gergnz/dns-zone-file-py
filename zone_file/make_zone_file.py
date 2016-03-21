from .record_processors import (
    process_origin, process_ttl, process_soa, process_ns, process_a,
    process_aaaa, process_cname, process_mx, process_ptr, process_txt,
    process_srv, process_spf, process_uri
)
from .configs import DEFAULT_TEMPLATE


def make_zone_file(json_zone_file, origin=None, ttl=None, template=None):
    """
    Generate the DNS zonefile, given a json-encoded description of the
    zone file (@json_zone_file) and the template to fill in (@template)

    json_zone_file = {
        "$ORIGIN": origin server,
        "$TTL":    default time-to-live,
        "SOA":     [ soa records ],
        "NS":      [ ns records ],
        "A":       [ a records ],
        "AAAA":    [ aaaa records ]
        "CNAME":   [ cname records ]
        "MX":      [ mx records ]
        "PTR":     [ ptr records ]
        "TXT":     [ txt records ]
        "SRV":     [ srv records ]
        "SPF":     [ spf records ]
        "URI":     [ uri records ]
    }
    """

    if template is None:
        template = DEFAULT_TEMPLATE[:]

    if origin is not None:
        json_zone_file['$ORIGIN'] = origin

    if ttl is not None:
        json_zone_file['$TTL'] = ttl

    soa_records = [json_zone_file.get('SOA')] if json_zone_file.get('SOA') else None

    zone_file = template
    zone_file = process_origin(json_zone_file.get('$ORIGIN', None), zone_file)
    zone_file = process_ttl(json_zone_file.get('$TTL', None), zone_file)
    zone_file = process_soa(soa_records, zone_file)
    zone_file = process_ns(json_zone_file.get('NS', None), zone_file)
    zone_file = process_a(json_zone_file.get('A', None), zone_file)
    zone_file = process_aaaa(json_zone_file.get('AAAA', None), zone_file)
    zone_file = process_cname(json_zone_file.get('CNAME', None), zone_file)
    zone_file = process_mx(json_zone_file.get('MX', None), zone_file)
    zone_file = process_ptr(json_zone_file.get('PTR', None), zone_file)
    zone_file = process_txt(json_zone_file.get('TXT', None), zone_file)
    zone_file = process_srv(json_zone_file.get('SRV', None), zone_file)
    zone_file = process_spf(json_zone_file.get('SPF', None), zone_file)
    zone_file = process_uri(json_zone_file.get('URI', None), zone_file)

    # remove newlines, but terminate with one
    zone_file = "\n".join(
        filter(
            lambda l: len(l.strip()) > 0, [tl.strip() for tl in zone_file.split("\n")]
        )
    ) + "\n"

    return zone_file
