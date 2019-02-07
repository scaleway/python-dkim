from libc.stdlib cimport malloc, free
from libc.string cimport memset
from dkim cimport signer_eml_header, signer_sign, signer_init, signer_quit
from email.message import EmailMessage
import exceptions


class CdkimSignerContextManager:
    def __enter__(self):
        signer_init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        signer_quit()

class Dkim:
    def __init__(self):
        self.dkim_statuses_to_exceptions = {
            1: exceptions.SignatureAvailableButFailed,
            2: exceptions.NoSignatureAvailable,
            3: exceptions.PublicKeyNotFound,
            4: exceptions.CantGetDomainKeyToVerify,
            5: exceptions.MessageNotValidSyntax,
            6: exceptions.RessourceUnavailable,
            7: exceptions.InternalError,
            8: exceptions.KeyFoundButHasBeenRevoked,
            11: exceptions.KeyRetrievalFailed,
            16: exceptions.GotMultipleDNSReplies,
            17: exceptions.SignatureGenerationFailed
        }

    def get_canonicalized_body(self):
        return '\r\n\r\n'.join(str(self.message).replace('\n', '\r\n' # A canonicalized mail body lines must end with a CRLF as per defined in RFC6376
                                                                     ).split('\r\n'*2)[1:]).encode()

    def _retrieve_original_case_sensitive_string_from_message(self, key):
        """Used as we don't want to force the user providing `headers` being in a case-sensitive form."""
        for header_key in self.message.keys():
            if key.lower() == header_key.lower():
                return header_key

        raise exceptions.SpecifiedHeaderDoesNotExistsInProvidedMessage()


class Signer(Dkim):
    def __init__(self, message: EmailMessage, selector: str, signing_domain: str, secret_key: bytes,
                 header_canon='relaxed', body_canon='relaxed', headers: list=None):
        """
        :param headers: A list of header keys to be included in the signature, the "From" header is absolutely mandatory
        as defined in RFC6376 hence not required in this list.
        :param message: The email message to be signed.
        :param selector: The domain selector used for the signature. The selector is used as a key
        for us to be able to retrieve our dkim public key for domain-registration verification.
        :param signing_domain: The domain name used for signing the email.
        :param secret_key: The raw-format RSA-private-key used to sign the email.
        :param header_canon: Canonicalizationo algorithm to use, either `"simple"` or `"relaxed"` (see RFC6376 for more details).
        """

        super().__init__()

        # Otherwise would be a mutable argument
        if headers is None:
            self.headers = {'from'}

        else:
            self.headers = set(header_key for header_key in headers)

            self.headers.add('from')

        self.message = message
        self.selector = selector
        self.signing_domain = signing_domain
        self.secret_key = secret_key
        self.header_canon = header_canon
        self.body_canon = body_canon


    def get_signature_header(self, normalized: bool=True) -> str:
        """
        :param normalized: Should the `"DKIM-Signature: "` string be included before the signature.
        :raises: Any of `exceptions` if unable to sign the message.
        """
        for header in self.headers:
            if not isinstance(header, str):
                raise TypeError("Argument 'headers' has incorrect type (expected List[str], got List[bytes])")

        allowed_canon = ('simple', 'relaxed')

        if self.header_canon not in allowed_canon or self.body_canon not in allowed_canon:
            raise ValueError('body_canon amd header_canon must be either `simple` or `relaxed` as per defined in RFC6376')

        cdef signer_sign_pm signer_sign_pm

        ## Allocate stack data
        # It must be done so that the objects created by encode persist in memory (encode creates temporary objects).
        # Then, they can be refered to using pointers.
        encoded_signing_domain = self.signing_domain.encode()
        encoded_selector = self.selector.encode()
        encoded_body = self.get_canonicalized_body()

        signer_sign_pm.signing_domain = encoded_signing_domain
        signer_sign_pm.selector = encoded_selector
        signer_sign_pm.body = encoded_body
        signer_sign_pm.body_size = len(signer_sign_pm.body)
        signer_sign_pm.secret_key = self.secret_key

        cdef unsigned char out_signature_buffer[SIGNER_MAX_OUTPUT_SIGNATURE_BUFFER_SIZE]
        memset(out_signature_buffer, 0, SIGNER_MAX_OUTPUT_SIGNATURE_BUFFER_SIZE)

        signer_sign_pm.out_signature_buffer = out_signature_buffer
        signer_sign_pm.out_signature_buffer_size = SIGNER_MAX_OUTPUT_SIGNATURE_BUFFER_SIZE

        signer_sign_pm.header_array_length = len(self.headers)
        signer_sign_pm.header_array = <signer_eml_header*> malloc(sizeof(signer_eml_header) * signer_sign_pm.header_array_length)

        signer_sign_pm.dkim_header_canon = 0 if self.header_canon == 'simple' else 1
        signer_sign_pm.dkim_body_canon = 0 if self.body_canon == 'simple' else 1

        if signer_sign_pm.header_array is NULL:
            raise MemoryError("Couldn't allocate memory for the header array")

        cdef int error_code
        try:
            for i, header in enumerate(self.headers):
                try:
                    encoded_header = '{}: {}'.format(
                        self._retrieve_original_case_sensitive_string_from_message(header),
                        self.message[header]).encode()

                except KeyError:
                    raise exceptions.SpecifiedHeaderDoesNotExistsInProvidedMessage("Header key {} wasn't found in message".format(header))

                signer_sign_pm.header_array[i].header = encoded_header
                signer_sign_pm.header_array[i].size = len(encoded_header)

            with CdkimSignerContextManager():
                error_code = signer_sign(&signer_sign_pm)

            if error_code in self.dkim_statuses_to_exceptions:
                raise self.dkim_statuses_to_exceptions[error_code]()

            elif error_code != DKIM_STAT_OK:
                raise RuntimeError(f"signer_sign returned the following error code {error_code}")

            signature = signer_sign_pm.out_signature_buffer.decode()

            if normalized:
                return "DKIM-Signature: " + signature

            return signature

        finally:
            free(signer_sign_pm.header_array)

    def add_signature_to_message(self) -> None:
        """Helper that adds the result of `self.get_signature_header` to the `message`"""

        self.message['DKIM-Signature'] = self.get_signature_header(normalized=False)


class Verifier(Dkim):
    def __init__(self, message: EmailMessage):
        super().__init__()

        self.message = message

    def verify(self) -> None:
        """
        Raises any of `exceptions` if unable to verify signature.
        """
        cdef signer_sign_pm signer_sign_pm

        headers = ['{field}: {value}'.format(field=field, value=value).encode() for field, value in self.message.items()]

        canonicalized_body = self.get_canonicalized_body()

        if not canonicalized_body.endswith(b'\r\n'):
            canonicalized_body += b'\r\n'

        signer_sign_pm.body = canonicalized_body
        signer_sign_pm.body_size = len(signer_sign_pm.body)

        signer_sign_pm.header_array_length = len(headers)
        signer_sign_pm.header_array = <signer_eml_header*> malloc(sizeof(signer_eml_header) * signer_sign_pm.header_array_length)

        if signer_sign_pm.header_array is NULL:
            raise MemoryError("Couldn't allocate memory for the header array")

        cdef int error_code
        try:
            for i, header in enumerate(headers):
                signer_sign_pm.header_array[i].header = header
                signer_sign_pm.header_array[i].size = len(header)

            with CdkimSignerContextManager():
                error_code = signer_verify(&signer_sign_pm)

            if error_code in self.dkim_statuses_to_exceptions:
                raise self.dkim_statuses_to_exceptions[error_code]()

            elif error_code != DKIM_STAT_OK:
                raise RuntimeError(f"signer_sign returned the following error code {error_code}")


        finally:
            free(signer_sign_pm.header_array)
