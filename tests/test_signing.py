import dkim
import unittest
from email.parser import Parser
import exceptions


class TestSigning(unittest.TestCase):
    """Generated signatures validity are not tested there as it's already done in the libopendkim project"""

    def setUp(self):
        self.private_key = "-----BEGIN RSA PRIVATE KEY-----\n" \
                           "MIICXQIBAAKBgQC4GUGr+d/6SFNzVLYpphnRd0QPGKz2uWnV65RAxa1Pw352Bqiz\n" \
                           "qiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFgF0gu3UJbNnu3+cd8k/kiQj+q\n" \
                           "4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3Dyc079gSLtnSrgXb+gQIDAQAB\n" \
                           "AoGAemlI0opm1Kvs2T4VliH8/tvX5FXbBH8LEZQAUwVeFTB/UQlieXyCV39pIxZO\n" \
                           "0Sa50qm8YNL9rb5HTSZiHQFOwyAKNqS4m/7JCsbuH4gQkPgPF561BHNL9oKfYgJq\n" \
                           "9P4kEFfDTBoXKBMxwWtT7AKV8dYvCa3vYzPQ/1BnqQdw2zECQQDyscdgR9Ih59PQ\n" \
                           "b72ddibdsxS65uXS2vzYLe7SKl+4R5JgJzw0M6DTAnoYFf6JAsKGZM15PCC0E16t\n" \
                           "RRo47U9VAkEAwjEVrlQ0/8yPACbDggDJg/Zz/uRu1wK0zjqj4vKjleubaX4SEvj7\n" \
                           "r6xxZm9hC1pMJAC9y3bbkbgCRBjXfyY6fQJBANe5aq2MaZ41wTOPf45NjbKXEiAo\n" \
                           "SbUpboKCIbyyaa8V/2h0t7D3C0dE9l4efsguqdZoF7Rh2/f1F70QpYRgfJkCQQCH\n" \
                           "oRrAeGXP50JVW72fNgeJGH/pnghgOa6of0JpxwhENJuGMZxUDfxTtUA6yD3iXP3j\n" \
                           "A3WL/wbaHsfOYf9Y+g1NAkAGLhx67Ah+uBNK4Xvfz0YPGINX20m+CMsxAw7FOaNv\n" \
                           "IW2oWFfZCB4APkIis79Ql45AHpavwx5XodBMzZwJUvlL\n" \
                           "-----END RSA PRIVATE KEY-----\n"
        self.headers = ['from']
        self.message = Parser().parsestr("""From: Example <example@example.com>
        
This is a message body.  Fun!
""")
        self.selector = "_dkim"
        self.signing_domain = "example.com"

    def test_successful_sign_normalized(self):
        self.assertIn('DKIM-Signature:', dkim.Signer(self.message, self.selector, self.signing_domain,
                                                     self.private_key.encode(),
                                                     headers=self.headers).get_signature_header())

    def test_successful_sign_not_normalized(self):
        self.assertNotIn('DKIM-Signature:', dkim.Signer(self.message, self.selector, self.signing_domain,
                                                        self.private_key.encode(),
                                                        headers=self.headers).get_signature_header(
            normalized=False))

    def test_malformed_header(self):
        signer = dkim.Signer(self.message, self.selector, self.signing_domain,
                             self.private_key.encode(), headers=['test'])

        self.assertRaises(exceptions.SpecifiedHeaderDoesNotExistsInProvidedMessage, signer.get_signature_header, normalized=True)

    def test_malformed_private_key(self):
        signer = dkim.Signer(self.message, self.selector, self.signing_domain,
                             b'test',
                             headers=self.headers)

        self.assertRaises(exceptions.RessourceUnavailable, signer.get_signature_header, normalized=True)

    def test_selector_too_long(self):
        signer = dkim.Signer(self.message, self.selector * 1024, self.signing_domain,
                             self.private_key.encode(),
                             headers=self.headers)

        self.assertRaises(exceptions.RessourceUnavailable, signer.get_signature_header, normalized=True)

    def test_domain_too_long(self):
        signer = dkim.Signer(self.message, self.selector, self.signing_domain * 1024,
                             self.private_key.encode(),
                             headers=self.headers)

        self.assertRaises(exceptions.RessourceUnavailable, signer.get_signature_header, normalized=True)

    def test_add_signature_to_message_helper(self):
        message = Parser().parsestr("""From: Example <example@example.com>
        
This is a message body.  Fun!
""")
        dkim.Signer(message, self.selector, self.signing_domain,
                    self.private_key.encode(),
                    headers=self.headers).add_signature_to_message()

        print(message)
        self.assertIn('DKIM-Signature', message)


if __name__ == '__main__':
    unittest.main()
