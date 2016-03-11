import json
import traceback
import unittest
from test import test_support
from zone_file import make_zone_file, parse_zone_file
from test_sample_data import zone_files

class ZoneFileTests(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_zone_file_creation(self):
        records = [
            {
                "name": "@", "ttl": "1D", "class": "IN", "type": "URI",
                "data": "mq9.s3.amazonaws.com/naval.id/profile.json"
            }
        ]
        zone_file = make_zone_file("ryan.id", "3600", records)
        print zone_file
        self.assertTrue(isinstance(zone_file, (unicode, str)))

    def test_zone_file_parsing(self):
        zone_file = parse_zone_file(zone_files["SAMPLE_1"])
        #print json.dumps(zone_file, indent=2)
        self.assertTrue(isinstance(zone_file, dict))

    def test_zone_file_parsing_2(self):
        zone_file = parse_zone_file(zone_files["SAMPLE_2"])
        #print json.dumps(zone_file, indent=2)
        self.assertTrue(isinstance(zone_file, dict))

    def test_zone_file_parsing_3(self):
        zone_file = parse_zone_file(zone_files["SAMPLE_3"])
        #print json.dumps(zone_file, indent=2)
        self.assertTrue(isinstance(zone_file, dict))

def test_main():
    test_support.run_unittest(
        ZoneFileTests
    )


if __name__ == '__main__':
    test_main()
