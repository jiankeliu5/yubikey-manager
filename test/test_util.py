# vim: set fileencoding=utf-8 :

from ykman.util import (b2len, derive_key, format_code, generate_static_pw,
                        hmac_shorten_key, modhex_decode, modhex_encode,
                        parse_tlvs, parse_truncated, time_challenge, Tlv)
import unittest


if not getattr(unittest.TestCase, 'assertRegex', None):
    # Python 2.7 can use assertRegexpMatches
    unittest.TestCase.assertRegex = unittest.TestCase.assertRegexpMatches


class TestUtilityFunctions(unittest.TestCase):

    def test_b2len(self):
        self.assertEqual(0x57, b2len(b'\x57'))
        self.assertEqual(0x1234, b2len(b'\x12\x34'))
        self.assertEqual(0xcafed00d, b2len(b'\xca\xfe\xd0\x0d'))

    def test_derive_key(self):
        self.assertEqual(
            b'\xb0}\xa1\xe7\xde\x87\xf8\x9a\x87\xa2\xb5\x98\xea\xa2\x18\x8c',
            derive_key(b'\0\0\0\0\0\0\0\0', u'foobar'))
        self.assertEqual(
            b'\xda\x81\x8ek,\xf0\xa2\xd0\xbf\x19\xb3\xdd\xd3K\x83\xf5',
            derive_key(b'12345678', u'Hallå världen!'))
        self.assertEqual(
            b'\xf3\xdf\xa7\x81T\xc8\x102\x99E\xfb\xc4\xb55\xe57',
            derive_key(b'saltsalt', u'Ťᶒśƫ ᵽĥřӓşḛ'))

    def test_format_code(self):
        self.assertEqual('000000', format_code(0))
        self.assertEqual('00000000', format_code(0, 8))
        self.assertEqual('345678', format_code(12345678))
        self.assertEqual('34567890', format_code(1234567890, 8))
        self.assertEqual('22222', format_code(0, steam=True))
        self.assertEqual('DVNKW', format_code(1234567890, steam=True))
        self.assertEqual('KDNYM', format_code(9999999999, steam=True))

    def test_generate_static_pw(self):
        for l in range(0, 38):
            self.assertRegex(generate_static_pw(l),
                             b'^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{' +
                             '{:d}'.format(l).encode('ascii') +
                             b'}$')

    def test_hmac_shorten_key(self):
        self.assertEqual(b'short', hmac_shorten_key(b'short', 'sha1'))
        self.assertEqual(b'x'*64, hmac_shorten_key(b'x'*64, 'sha1'))
        self.assertEqual(
            b'0\xec\xd3\xf4\xb5\xcej\x1a\xc6x'
            b'\x15\xdb\xa1\xfb\x7f\x9f\xff\x00`\x14',
            hmac_shorten_key(b'l'*65, 'sha1')
        )
        self.assertEqual(b'x'*64, hmac_shorten_key(b'x'*64, 'sha256'))
        self.assertEqual(
            b'l\xf9\x08}"vi\xbcj\xa9\nlkQ\x81\xd9`'
            b'\xbb\x88\xe9L4\x0b\xbd?\x07s/K\xae\xb9L',
            hmac_shorten_key(b'l'*65, 'sha256')
        )

    def test_modhex_decode(self):
        self.assertEqual(b'', modhex_decode(''))
        self.assertEqual(b'\x2d\x34\x4e\x83', modhex_decode('dteffuje'))
        self.assertEqual(
            b'\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56',
            modhex_decode('hknhfjbrjnlnldnhcujvddbikngjrtgh')
        )

    def test_modhex_encode(self):
        self.assertEqual('', modhex_encode(b''))
        self.assertEqual('dteffuje', modhex_encode(b'\x2d\x34\x4e\x83'))
        self.assertEqual(
            'hknhfjbrjnlnldnhcujvddbikngjrtgh',
            modhex_encode(b'\x69\xb6\x48\x1c\x8b\xab\xa2\xb6'
                          b'\x0e\x8f\x22\x17\x9b\x58\xcd\x56')
        )

    def test_parse_tlvs(self):
        tlvs = parse_tlvs(b'\x00\x02\xd0\x0d\xa1\x00\xff\x04\xfe\xed\xfa\xce')
        self.assertEqual(3, len(tlvs))

        self.assertEqual(0, tlvs[0].tag)
        self.assertEqual(2, tlvs[0].length)
        self.assertEqual(b'\xd0\x0d', tlvs[0].value)

        self.assertEqual(0xa1, tlvs[1].tag)
        self.assertEqual(0, tlvs[1].length)
        self.assertEqual(b'', tlvs[1].value)

        self.assertEqual(0xff, tlvs[2].tag)
        self.assertEqual(4, tlvs[2].length)
        self.assertEqual(b'\xfe\xed\xfa\xce', tlvs[2].value)

    def test_parse_truncated(self):
        self.assertEqual(0x01020304, parse_truncated(b'\1\2\3\4'))
        self.assertEqual(0xdeadbeef & 0x7fffffff,
                         parse_truncated(b'\xde\xad\xbe\xef'))

    def test_time_challenge(self):
        self.assertEqual(b'\0'*8, time_challenge(0))
        self.assertEqual(b'\x00\x00\x00\x00\x00\x06G\x82',
                         time_challenge(12345678))
        self.assertEqual(b'\x00\x00\x00\x00\x02\xf2\xeaC',
                         time_challenge(1484223461.2644958))

    def test_tlv(self):
        self.assertEqual(Tlv(b'\xff\6foobar'), Tlv(0xff, b'foobar'))

        tlv1 = Tlv(b'\0\5hello')
        tlv2 = Tlv(0xff, b'')
        tlv3 = Tlv(0x12, b'hi'*200)

        self.assertEqual(b'\0\5hello', tlv1)
        self.assertEqual(b'\xff\0', tlv2)
        self.assertEqual(b'\x12\x82\x01\x90' + b'hi'*200, tlv3)

        self.assertEqual(b'\0\5hello\xff\0\x12\x82\x01\x90' + b'hi'*200,
                         tlv1 + tlv2 + tlv3)
