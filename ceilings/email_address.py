from email_validator import validate_email


class UnsupportedLocalPart(ValueError):
    """The local SMTP transport requires ASCII before the @ sign."""


def login_address(value):
    address = validate_email(value, check_deliverability=False)
    if address.smtputf8:
        raise UnsupportedLocalPart("Use ASCII characters before @. Internationalized domains are supported.")
    return address
