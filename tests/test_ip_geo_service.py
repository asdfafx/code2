import unittest

from app.services.ip_geo import IPGeoService


class IPGeoServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.service = IPGeoService()

    def test_classifies_loopback_private_link_local_and_reserved_ranges(self):
        cases = [
            ("127.0.0.1", "本地网络", "回环地址"),
            ("10.0.0.1", "本地网络", "私有地址"),
            ("172.16.0.1", "本地网络", "私有地址"),
            ("192.168.1.1", "本地网络", "私有地址"),
            ("169.254.10.20", "保留地址", "链路本地地址"),
            ("240.0.0.1", "保留地址", "保留地址"),
        ]

        for ip_address, country, region in cases:
            with self.subTest(ip_address=ip_address):
                result = self.service.query_ip_location(ip_address)
                self.assertEqual(result["country"], country)
                self.assertEqual(result["region"], region)
                self.assertEqual(result["ip"], ip_address)
                self.assertTrue(result["is_private"])

    def test_does_not_treat_non_private_172_block_as_local_network(self):
        class DeterministicGeoService(IPGeoService):
            def _query_baidu_api(self, ip_address):
                return None

            def _query_international_api(self, ip_address):
                return {
                    "ip": ip_address,
                    "country": "公网地址",
                    "region": "外部网络",
                    "city": "外部",
                    "latitude": None,
                    "longitude": None,
                    "is_private": False,
                    "source": "test"
                }

        result = DeterministicGeoService().query_ip_location("172.32.0.1")

        self.assertNotEqual(result["country"], "本地网络")
        self.assertEqual(result["source"], "test")


if __name__ == "__main__":
    unittest.main()
