from __future__ import annotations

import logging
import random
import re
import string
from collections.abc import Iterable
from datetime import UTC, datetime
from hashlib import sha256
from typing import Literal, cast

from django.conf import settings
from django.contrib.auth.models import User
from django.core.validators import MinLengthValidator
from django.db import models, transaction
from django.db.models.base import ModelBase

from api.exceptions import ErrorContextType, RelayAPIException
from privaterelay.utils import flag_is_active_in_task

from .utils import get_domains_from_settings, incr_if_enabled
from .validators import has_bad_words, is_blocklisted, valid_available_subdomain

logger = logging.getLogger("events")


DOMAIN_CHOICES = [(1, "RELAY_FIREFOX_DOMAIN"), (2, "MOZMAIL_DOMAIN")]


# This function is referenced in migration
# 0024_increase_subdomain_length
assert callable(valid_available_subdomain)  # noqa: S101 (use of assert)


# This historical function is referenced in migration
# 0029_profile_add_deleted_metric_and_changeserver_storage_default
def default_server_storage():
    return True


def default_domain_numerical():
    domains = get_domains_from_settings()
    domain = domains["MOZMAIL_DOMAIN"]
    return get_domain_numerical(domain)


def address_hash(address, subdomain=None, domain=None):
    if not domain:
        domain = get_domains_from_settings()["MOZMAIL_DOMAIN"]
    if subdomain:
        return sha256(f"{address}@{subdomain}.{domain}".encode()).hexdigest()
    if domain == settings.RELAY_FIREFOX_DOMAIN:
        return sha256(f"{address}".encode()).hexdigest()
    return sha256(f"{address}@{domain}".encode()).hexdigest()


def address_default():
    return "".join(
        random.choices(  # noqa: S311 (standard pseudo-random generator used)
            string.ascii_lowercase + string.digits, k=9
        )
    )


def get_domain_numerical(domain_address):
    # get domain name from the address
    domains = get_domains_from_settings()
    domains_keys = list(domains.keys())
    domains_values = list(domains.values())
    domain_name = domains_keys[domains_values.index(domain_address)]
    # get domain numerical value from domain name
    choices = dict(DOMAIN_CHOICES)
    choices_keys = list(choices.keys())
    choices_values = list(choices.values())
    return choices_keys[choices_values.index(domain_name)]


def hash_subdomain(subdomain, domain=settings.MOZMAIL_DOMAIN):
    return sha256(f"{subdomain}.{domain}".encode()).hexdigest()


class RegisteredSubdomain(models.Model):
    subdomain_hash = models.CharField(max_length=64, db_index=True, unique=True)
    registered_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.subdomain_hash


class CannotMakeAddressException(RelayAPIException):
    """Base exception for RelayAddress or DomainAddress creation failure."""


class AccountIsPausedException(CannotMakeAddressException):
    default_code = "account_is_paused"
    default_detail = "Your account is on pause."
    status_code = 403


class AccountIsInactiveException(CannotMakeAddressException):
    default_code = "account_is_inactive"
    default_detail = "Your account is not active."
    status_code = 403


class RelayAddrFreeTierLimitException(CannotMakeAddressException):
    default_code = "free_tier_limit"
    default_detail_template = (
        "You’ve used all {free_tier_limit} email masks included with your free account."
        " You can reuse an existing mask, but using a unique mask for each account is"
        " the most secure option."
    )
    status_code = 403

    def __init__(self, free_tier_limit: int | None = None):
        self.free_tier_limit = free_tier_limit or settings.MAX_NUM_FREE_ALIASES
        super().__init__()

    def error_context(self) -> ErrorContextType:
        return {"free_tier_limit": self.free_tier_limit}


class DomainAddrFreeTierException(CannotMakeAddressException):
    default_code = "free_tier_no_subdomain_masks"
    default_detail = (
        "Your free account does not include custom subdomains for masks."
        " To create custom masks, upgrade to Relay Premium."
    )
    status_code = 403


class DomainAddrNeedSubdomainException(CannotMakeAddressException):
    default_code = "need_subdomain"
    default_detail = "Please select a subdomain before creating a custom email address."
    status_code = 400


class DomainAddrUpdateException(CannotMakeAddressException):
    """Exception raised when attempting to edit an existing domain address field."""

    default_code = "address_not_editable"
    default_detail = "You cannot edit an existing domain address field."
    status_code = 400


class DomainAddrUnavailableException(CannotMakeAddressException):
    default_code = "address_unavailable"
    default_detail_template = (
        "“{unavailable_address}” could not be created."
        " Please try again with a different mask name."
    )
    status_code = 400

    def __init__(self, unavailable_address: str):
        self.unavailable_address = unavailable_address
        super().__init__()

    def error_context(self) -> ErrorContextType:
        return {"unavailable_address": self.unavailable_address}


class DomainAddrDuplicateException(CannotMakeAddressException):
    default_code = "duplicate_address"
    default_detail_template = (
        "“{duplicate_address}” already exists."
        " Please try again with a different mask name."
    )
    status_code = 409

    def __init__(self, duplicate_address: str):
        self.duplicate_address = duplicate_address
        super().__init__()

    def error_context(self) -> ErrorContextType:
        return {"duplicate_address": self.duplicate_address}


class RelayAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    address = models.CharField(max_length=64, default=address_default, unique=True)
    domain = models.PositiveSmallIntegerField(
        choices=DOMAIN_CHOICES, default=default_domain_numerical
    )
    enabled = models.BooleanField(default=True)
    description = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_modified_at = models.DateTimeField(auto_now=True, db_index=True)
    last_used_at = models.DateTimeField(blank=True, null=True)
    num_forwarded = models.PositiveIntegerField(default=0)
    num_blocked = models.PositiveIntegerField(default=0)
    num_level_one_trackers_blocked = models.PositiveIntegerField(default=0, null=True)
    num_replied = models.PositiveIntegerField(default=0)
    num_spam = models.PositiveIntegerField(default=0)
    generated_for = models.CharField(max_length=255, blank=True)
    block_list_emails = models.BooleanField(default=False)
    used_on = models.TextField(default=None, blank=True, null=True)

    class Meta:
        indexes = [
            # Find when a user first used the add-on
            models.Index(
                name="idx_ra_created_by_addon",
                fields=["user"],
                condition=~models.Q(generated_for__exact=""),
                include=["created_at"],
            ),
        ]

    def __str__(self):
        return self.address

    def delete(self, *args, **kwargs):
        # TODO: create hard bounce receipt rule in AWS for the address
        deleted_address = DeletedAddress.objects.create(
            address_hash=address_hash(self.address, domain=self.domain_value),
            num_forwarded=self.num_forwarded,
            num_blocked=self.num_blocked,
            num_replied=self.num_replied,
            num_spam=self.num_spam,
        )
        deleted_address.save()
        profile = self.user.profile
        profile.refresh_from_db()
        profile.address_last_deleted = datetime.now(UTC)
        profile.num_address_deleted += 1
        profile.num_email_forwarded_in_deleted_address += self.num_forwarded
        profile.num_email_blocked_in_deleted_address += self.num_blocked
        profile.num_level_one_trackers_blocked_in_deleted_address = (
            profile.num_level_one_trackers_blocked_in_deleted_address or 0
        ) + (self.num_level_one_trackers_blocked or 0)
        profile.num_email_replied_in_deleted_address += self.num_replied
        profile.num_email_spam_in_deleted_address += self.num_spam
        profile.num_deleted_relay_addresses += 1
        profile.last_engagement = datetime.now(UTC)
        profile.save()
        return super().delete(*args, **kwargs)

    def save(
        self,
        force_insert: bool | tuple[ModelBase, ...] = False,
        force_update: bool = False,
        using: str | None = None,
        update_fields: Iterable[str] | None = None,
    ) -> None:
        from privaterelay.models import Profile

        if self._state.adding:
            with transaction.atomic():
                locked_profile = Profile.objects.select_for_update().get(user=self.user)
                check_user_can_make_another_address(locked_profile.user)
                while True:
                    address_is_allowed = not is_blocklisted(self.address)
                    address_is_valid = valid_address(self.address, self.domain_value)
                    if address_is_valid and address_is_allowed:
                        break
                    self.address = address_default()
                locked_profile.update_abuse_metric(address_created=True)
                locked_profile.last_engagement = datetime.now(UTC)
                locked_profile.save()
        if (not self.user.profile.server_storage) and any(
            (self.description, self.generated_for, self.used_on)
        ):
            self.description = ""
            self.generated_for = ""
            self.used_on = ""
            if update_fields is not None:
                update_fields = {"description", "generated_for", "used_on"}.union(
                    update_fields
                )
        if not self.user.profile.has_premium and self.block_list_emails:
            self.block_list_emails = False
            if update_fields is not None:
                update_fields = {"block_list_emails"}.union(update_fields)
        super().save(
            force_insert=force_insert,
            force_update=force_update,
            using=using,
            update_fields=update_fields,
        )

    @property
    def domain_value(self) -> str:
        domain = cast(
            Literal["RELAY_FIREFOX_DOMAIN", "MOZMAIL_DOMAIN"], self.get_domain_display()
        )
        return get_domains_from_settings()[domain]

    @property
    def full_address(self) -> str:
        return f"{self.address}@{self.domain_value}"

    @property
    def metrics_id(self) -> str:
        if not self.id:
            raise ValueError("self.id must be truthy value.")
        # Prefix with 'R' for RelayAddress, since there may be a DomainAddress with the
        # same row ID
        return f"R{self.id}"


def check_user_can_make_another_address(user: User) -> None:
    if not user.is_active:
        raise AccountIsInactiveException()

    if user.profile.is_flagged:
        raise AccountIsPausedException()
    # MPP-3021: return early for premium users to avoid at_max_free_aliases DB query
    if user.profile.has_premium:
        return
    if user.profile.at_max_free_aliases:
        raise RelayAddrFreeTierLimitException()


def valid_address_pattern(address):
    #   can't start or end with a hyphen
    #   must be 1-63 lowercase alphanumeric characters and/or hyphens
    valid_address_pattern = re.compile("^(?![-.])[a-z0-9-.]{1,63}(?<![-.])$")
    return valid_address_pattern.match(address) is not None


def valid_address(address: str, domain: str, subdomain: str | None = None) -> bool:
    address_pattern_valid = valid_address_pattern(address)
    address_contains_badword = has_bad_words(address)
    address_already_deleted = 0
    if not subdomain or flag_is_active_in_task(
        "custom_domain_management_redesign", None
    ):
        address_already_deleted = DeletedAddress.objects.filter(
            address_hash=address_hash(address, domain=domain, subdomain=subdomain)
        ).count()
    if (
        address_already_deleted > 0
        or address_contains_badword
        or not address_pattern_valid
    ):
        return False
    return True


class DeletedAddress(models.Model):
    address_hash = models.CharField(max_length=64, db_index=True)
    num_forwarded = models.PositiveIntegerField(default=0)
    num_blocked = models.PositiveIntegerField(default=0)
    num_replied = models.PositiveIntegerField(default=0)
    num_spam = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.address_hash


def check_user_can_make_domain_address(user: User) -> None:
    if not user.profile.has_premium:
        raise DomainAddrFreeTierException()

    if not user.profile.subdomain:
        raise DomainAddrNeedSubdomainException()

    if not user.profile.user.is_active:
        raise AccountIsInactiveException()

    if user.profile.is_flagged:
        raise AccountIsPausedException()


class DomainAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    address = models.CharField(
        max_length=64, validators=[MinLengthValidator(limit_value=1)]
    )
    enabled = models.BooleanField(default=True)
    description = models.CharField(max_length=64, blank=True)
    domain = models.PositiveSmallIntegerField(choices=DOMAIN_CHOICES, default=2)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    first_emailed_at = models.DateTimeField(null=True, db_index=True)
    last_modified_at = models.DateTimeField(auto_now=True, db_index=True)
    last_used_at = models.DateTimeField(blank=True, null=True)
    num_forwarded = models.PositiveIntegerField(default=0)
    num_blocked = models.PositiveIntegerField(default=0)
    num_level_one_trackers_blocked = models.PositiveIntegerField(default=0, null=True)
    num_replied = models.PositiveIntegerField(default=0)
    num_spam = models.PositiveIntegerField(default=0)
    block_list_emails = models.BooleanField(default=False)
    used_on = models.TextField(default=None, blank=True, null=True)

    class Meta:
        unique_together = ["user", "address"]

    def __str__(self):
        return self.address

    def save(
        self,
        force_insert: bool | tuple[ModelBase, ...] = False,
        force_update: bool = False,
        using: str | None = None,
        update_fields: Iterable[str] | None = None,
    ) -> None:
        user_profile = self.user.profile
        if self._state.adding:
            check_user_can_make_domain_address(self.user)
            domain_address_valid = valid_address(
                self.address, self.domain_value, user_profile.subdomain
            )
            if not domain_address_valid:
                if self.first_emailed_at:
                    incr_if_enabled("domainaddress.create_via_email_fail")
                raise DomainAddrUnavailableException(unavailable_address=self.address)

            if DomainAddress.objects.filter(
                user=self.user, address=self.address
            ).exists():
                raise DomainAddrDuplicateException(duplicate_address=self.address)

            user_profile.update_abuse_metric(address_created=True)
            user_profile.last_engagement = datetime.now(UTC)
            user_profile.save(update_fields=["last_engagement"])
            incr_if_enabled("domainaddress.create")
            if self.first_emailed_at:
                incr_if_enabled("domainaddress.create_via_email")
        else:
            # The model is in an update state, do not allow 'address' field updates
            existing_instance = DomainAddress.objects.get(id=self.id)
            if existing_instance.address != self.address:
                raise DomainAddrUpdateException()

        if not user_profile.has_premium and self.block_list_emails:
            self.block_list_emails = False
            if update_fields:
                update_fields = {"block_list_emails"}.union(update_fields)
        if (not user_profile.server_storage) and (self.description or self.used_on):
            self.description = ""
            self.used_on = ""
            if update_fields:
                update_fields = {"description", "used_on"}.union(update_fields)
        super().save(
            force_insert=force_insert,
            force_update=force_update,
            using=using,
            update_fields=update_fields,
        )

    @staticmethod
    def make_domain_address(
        user: User, address: str | None = None, made_via_email: bool = False
    ) -> DomainAddress:
        check_user_can_make_domain_address(user)

        if not address:
            # FIXME: if the alias is randomly generated and has bad words
            # we should retry like make_relay_address does
            # not fixing this now because not sure randomly generated
            # DomainAlias will be a feature
            address = address_default()
            # Only check for bad words if randomly generated
        if not isinstance(address, str):
            raise TypeError("address must be type str")

        first_emailed_at = datetime.now(UTC) if made_via_email else None
        domain_address = DomainAddress.objects.create(
            user=user, address=address, first_emailed_at=first_emailed_at
        )
        return domain_address

    def delete(self, *args, **kwargs):
        # TODO: create hard bounce receipt rule in AWS for the address
        deleted_address = DeletedAddress.objects.create(
            address_hash=address_hash(
                self.address, self.user.profile.subdomain, self.domain_value
            ),
            num_forwarded=self.num_forwarded,
            num_blocked=self.num_blocked,
            num_replied=self.num_replied,
            num_spam=self.num_spam,
        )
        deleted_address.save()
        profile = self.user.profile
        profile.address_last_deleted = datetime.now(UTC)
        profile.num_address_deleted += 1
        profile.num_email_forwarded_in_deleted_address += self.num_forwarded
        profile.num_email_blocked_in_deleted_address += self.num_blocked
        profile.num_level_one_trackers_blocked_in_deleted_address = (
            profile.num_level_one_trackers_blocked_in_deleted_address or 0
        ) + (self.num_level_one_trackers_blocked or 0)
        profile.num_email_replied_in_deleted_address += self.num_replied
        profile.num_email_spam_in_deleted_address += self.num_spam
        profile.num_deleted_domain_addresses += 1
        profile.last_engagement = datetime.now(UTC)
        profile.save()
        return super().delete(*args, **kwargs)

    @property
    def domain_value(self) -> str:
        domain = cast(
            Literal["RELAY_FIREFOX_DOMAIN", "MOZMAIL_DOMAIN"], self.get_domain_display()
        )
        return get_domains_from_settings()[domain]

    @property
    def full_address(self) -> str:
        return f"{self.address}@{self.user.profile.subdomain}.{self.domain_value}"

    @property
    def metrics_id(self) -> str:
        if not self.id:
            raise ValueError("self.id must be truthy value.")
        # Prefix with 'D' for DomainAddress, since there may be a RelayAddress with the
        # same row ID
        return f"D{self.id}"


class Reply(models.Model):
    relay_address = models.ForeignKey(
        RelayAddress, on_delete=models.CASCADE, blank=True, null=True
    )
    domain_address = models.ForeignKey(
        DomainAddress, on_delete=models.CASCADE, blank=True, null=True
    )
    lookup = models.CharField(max_length=255, blank=False, db_index=True)
    encrypted_metadata = models.TextField(blank=False)
    created_at = models.DateField(auto_now_add=True, null=False, db_index=True)

    @property
    def address(self):
        return self.relay_address or self.domain_address

    @property
    def profile(self):
        return self.address.user.profile

    @property
    def owner_has_premium(self):
        return self.profile.has_premium

    def increment_num_replied(self):
        address = self.relay_address or self.domain_address
        if not address:
            raise ValueError("address must be truthy value")
        address.num_replied += 1
        address.last_used_at = datetime.now(UTC)
        address.save(update_fields=["num_replied", "last_used_at"])
        return address.num_replied
