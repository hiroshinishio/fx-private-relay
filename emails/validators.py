"""Data validation for emails."""

import re

from django.core.exceptions import BadRequest

from .apps import emails_config


class CannotMakeSubdomainException(BadRequest):
    """Exception raised by Profile due to error on subdomain creation.

    Attributes:
        message -- optional explanation of the error
    """

    def __init__(self, message=None):
        self.message = message


def valid_available_subdomain(subdomain, *args, **kwargs):
    from .models import RegisteredSubdomain, hash_subdomain

    if not subdomain:
        raise CannotMakeSubdomainException("error-subdomain-cannot-be-empty-or-null")
    # valid subdomains:
    #   can't start or end with a hyphen
    #   must be 1-63 alphanumeric characters and/or hyphens
    subdomain = subdomain.lower()
    valid_subdomain_pattern = re.compile("^(?!-)[a-z0-9-]{1,63}(?<!-)$")
    valid = valid_subdomain_pattern.match(subdomain) is not None
    #   can't have "bad" words in them
    bad_word = has_bad_words(subdomain)
    #   can't have "blocked" words in them
    blocked_word = is_blocklisted(subdomain)
    #   can't be taken by someone else
    taken = (
        RegisteredSubdomain.objects.filter(
            subdomain_hash=hash_subdomain(subdomain)
        ).count()
        > 0
    )
    if not valid or bad_word or blocked_word or taken:
        raise CannotMakeSubdomainException("error-subdomain-not-available")
    return True


def has_bad_words(value: str) -> bool:
    for badword in emails_config().badwords:
        badword = badword.strip()
        if len(badword) <= 4 and badword == value:
            return True
        if len(badword) > 4 and badword in value:
            return True
    return False


def is_blocklisted(value: str) -> bool:
    return any(blockedword == value for blockedword in emails_config().blocklist)
