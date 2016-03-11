import json
from jinja2 import Environment, PackageLoader

def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def get_plaintext_records_from_lines(lines):
    records = []
    current_record = ""
    in_parentheses = False
    for line in lines:
        line = line.split(';')[0].replace("\n", "").strip()
        if len(line) == 0:
            continue
        if in_parentheses:
            if line.find(")") > -1:
                current_record += line
                records.append(current_record)
                current_record = ""
                in_parentheses = False
            else:
                current_record += line + ", "
        else:
            if line.find("(") > -1:
                current_record += line + " "
                in_parentheses = True
            else:
                current_record += line
                records.append(current_record)
                current_record = ""
    return records

def get_json_record_from_plaintext(plaintext_record):
    record_parts = plaintext_record.split()
    record_name, record_ttl, record_class, record_type, record_data = None, None, None, None, None
    if len(record_parts) < 4:
        if record_parts[0] == "":
            pass
    elif len(record_parts) == 4:
        if record_parts[1] == "IN":
            record_name, record_class, record_type, record_data = record_parts
    elif len(record_parts) == 5:
        if record_parts[2] == "IN":
            record_name, record_ttl, record_class, record_type, record_data = record_parts
    elif len(record_parts) == 6:
        if record_parts[3] == "(":
            pass
    else:
        if record_parts[2] == "SOA":
            record_name, record_ttl, record_class, record_type, record_data = record_parts[0:5]

    record = None
    if record_name and record_class and record_type and record_data:
        record = {
            "name": record_name,
            "class": record_class,
            "type": record_type,
            "data": record_data
        }
        if record_ttl:
            record["ttl"] = record_ttl
    return record

def parse_zone_file(zone_file):
    """
    """
    origin = None
    ttl = None
    lines = zone_file.split('\n')
    plaintext_records = get_plaintext_records_from_lines(lines)
    records = []
    for plaintext_record in plaintext_records:
        if plaintext_record.startswith("$ORIGIN"):
            origin = plaintext_record.split("$ORIGIN")[1]
        elif plaintext_record.startswith("$TTL"):
            ttl = plaintext_record.split("$TTL")[1]
        else:
            record = get_json_record_from_plaintext(plaintext_record)
            if record:
                records.append(record)
    json_zone_file = {
        "origin": origin,
        "ttl": ttl,
        "records": records
    }
    return json_zone_file

def make_zone_file(origin, ttl, records):
    """
    """
    zone_file = ""

    if origin:
        zone_file += "$ORIGIN %s\n" % origin
    if ttl:
        zone_file += "$TTL %s\n" % ttl
    
    for record in records:
        if not ("name" in record and "class" in record and "type" in record \
                and "data" in record):
            raise ValueError("Invalid record")
        if "ttl" in record:
            zone_file += "%s %s %s %s %s\n" % (
                record["name"], record["ttl"], record["class"], record["type"],
                record["data"])
        else:
            zone_file += "%s %s %s %s\n" % (
                record["name"], record["class"], record["type"], record["data"])

    if zone_file[-1] == '\n':
        zone_file = zone_file[0:-1]

    return zone_file
