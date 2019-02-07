import dkim
from email.parser import Parser


def main():
    message = """From: Example <example@example.com>
This is a message body.  Fun!
"""
    selector = "_dkim"
    signing_domain = "example.com"
    secret_key = "-----BEGIN RSA PRIVATE KEY-----\n" \
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

    message = Parser().parsestr(text=message)
    dkim.Signer(message, selector, signing_domain, secret_key.encode()).add_signature_to_message()
    print(message.as_string())


if __name__ == '__main__':
    main()
