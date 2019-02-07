class DkimException(Exception):
    def __init__(self, message=''):
        self.message = message

    def __str__(self):
        return str(self.message)


class UnableToSign(DkimException):
    def __init__(self,
                 message='Either unable to load the specified private key, maybe it is invalid? Or generated signature too large, try to reduce header count. Double-check that message body is in canonical form.'):
        self.message = message


class InvalidHeaders(DkimException):
    def __init__(self, message='One or more specified headers are invalid.'):
        self.message = message


class SpecifiedHeaderDoesNotExistsInProvidedMessage(DkimException):
    pass


class SignatureAvailableButFailed(DkimException):
    pass


class NoSignatureAvailable(DkimException):
    pass


class PublicKeyNotFound(DkimException):
    pass


class CantGetDomainKeyToVerify(DkimException):
    pass


class MessageNotValidSyntax(DkimException):
    pass


class RessourceUnavailable(DkimException):
    pass


class InternalError(DkimException):
    pass


class KeyFoundButHasBeenRevoked(DkimException):
    pass


class KeyRetrievalFailed(DkimException):
    pass


class GotMultipleDNSReplies(DkimException):
    pass


class SignatureGenerationFailed(DkimException):
    pass
