"""DNS Authenticator for PowerAdmin."""
from __future__ import annotations

import logging
from typing import Any, Callable, Optional

import requests

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

DEFAULT_API_VERSION = "v2"
SUPPORTED_API_VERSIONS = ("v1", "v2")


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for PowerAdmin.

    This Authenticator uses the PowerAdmin API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using PowerAdmin for DNS)."
    ttl = 120

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(
        cls, add: Callable[..., None], default_propagation_seconds: int = 120
    ) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="PowerAdmin credentials INI file.")

    def more_info(self) -> str:
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge "
            "using the PowerAdmin API."
        )

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "PowerAdmin credentials INI file",
            None,
            self._validate_credentials,
        )

    def _validate_credentials(self, credentials: CredentialsConfiguration) -> None:
        api_url = credentials.conf("api-url")
        api_key = credentials.conf("api-key")
        api_version = credentials.conf("api-version")

        if not api_url:
            raise errors.PluginError("PowerAdmin API URL is required (dns_poweradmin_api_url)")
        if not api_key:
            raise errors.PluginError("PowerAdmin API key is required (dns_poweradmin_api_key)")
        if api_version and api_version not in SUPPORTED_API_VERSIONS:
            raise errors.PluginError(
                f"Invalid API version: {api_version}. "
                f"Supported versions: {', '.join(SUPPORTED_API_VERSIONS)}"
            )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_poweradmin_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_poweradmin_client().del_txt_record(domain, validation_name, validation)

    def _get_poweradmin_client(self) -> _PowerAdminClient:
        if self.credentials is None:
            raise errors.PluginError("Credentials not configured")

        api_version = self.credentials.conf("api-version") or DEFAULT_API_VERSION

        return _PowerAdminClient(
            api_url=self.credentials.conf("api-url"),
            api_key=self.credentials.conf("api-key"),
            api_version=api_version,
        )


class _PowerAdminClient:
    """Encapsulates all communication with the PowerAdmin API."""

    def __init__(self, api_url: str, api_key: str, api_version: str = "v2") -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.api_version = api_version
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def add_txt_record(
        self, domain: str, record_name: str, record_content: str, record_ttl: int
    ) -> None:
        """Add a TXT record using the PowerAdmin API.

        Args:
            domain: The domain to use for finding the zone.
            record_name: The record name (FQDN, e.g., _acme-challenge.example.com).
            record_content: The record content (validation token).
            record_ttl: The record TTL in seconds.
        """
        zone_id, zone_name = self._find_zone_id(domain)
        if zone_id is None:
            raise errors.PluginError(
                f"Unable to find a PowerAdmin zone for {domain}"
            )

        # Check if a record already exists (idempotent)
        existing_record = self._find_txt_record(zone_id, record_name, record_content)
        if existing_record is not None:
            logger.debug("TXT record already exists, skipping creation")
            return

        # Create the TXT record
        record_data = {
            "name": record_name,
            "type": "TXT",
            "content": record_content,
            "ttl": record_ttl,
        }

        url = f"{self.api_url}/api/{self.api_version}/zones/{zone_id}/records"
        try:
            response = self.session.post(url, json=record_data)
            response.raise_for_status()
            logger.debug("Successfully added TXT record for %s", record_name)
        except requests.exceptions.HTTPError as e:
            hint = self._get_error_hint(e.response)
            raise errors.PluginError(
                f"Error adding TXT record: {e}{hint}"
            )
        except requests.exceptions.RequestException as e:
            raise errors.PluginError(f"Error communicating with PowerAdmin API: {e}")

    def del_txt_record(
        self, domain: str, record_name: str, record_content: str
    ) -> None:
        """Delete a TXT record using the PowerAdmin API.

        Args:
            domain: The domain to use for finding the zone.
            record_name: The record name (FQDN).
            record_content: The record content (validation token).
        """
        try:
            zone_id, zone_name = self._find_zone_id(domain)
            if zone_id is None:
                logger.debug("Unable to find zone for %s during cleanup", domain)
                return

            record = self._find_txt_record(zone_id, record_name, record_content)
            if record is None:
                logger.debug("TXT record not found for %s during cleanup", record_name)
                return

            record_id = record.get("id")
            if record_id is None:
                logger.warning("Record found but has no ID, cannot delete")
                return

            url = f"{self.api_url}/api/{self.api_version}/zones/{zone_id}/records/{record_id}"
            response = self.session.delete(url)
            response.raise_for_status()
            logger.debug("Successfully deleted TXT record for %s", record_name)

        except requests.exceptions.RequestException as e:
            logger.warning("Error deleting TXT record during cleanup: %s", e)

    def _find_zone_id(self, domain: str) -> tuple[Optional[int], Optional[str]]:
        """Find the zone ID for a given domain.

        Args:
            domain: The domain being validated.

        Returns:
            Tuple of (zone_id, zone_name) or (None, None) if not found.
        """
        zone_name_guesses = dns_common.base_domain_name_guesses(domain)

        for zone_name in zone_name_guesses:
            logger.debug("Looking for zone: %s", zone_name)
            zone_id = self._get_zone_id_by_name(zone_name)
            if zone_id is not None:
                logger.debug("Found zone %s with ID %s", zone_name, zone_id)
                return zone_id, zone_name

        return None, None

    def _get_zone_id_by_name(self, zone_name: str) -> Optional[int]:
        """Get zone ID by zone name from PowerAdmin API.

        Args:
            zone_name: The zone name to look up.

        Returns:
            The zone ID if found, None otherwise.
        """
        url = f"{self.api_url}/api/{self.api_version}/zones"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            zones = response.json()

            # Handle both list and dict response formats
            if isinstance(zones, dict) and "data" in zones:
                zones = zones["data"]

            for zone in zones:
                # Zone name might be stored with or without a trailing dot
                zone_stored_name = zone.get("name", "").rstrip(".")
                if zone_stored_name == zone_name or zone_stored_name == zone_name.rstrip("."):
                    return zone.get("id")

            return None

        except requests.exceptions.RequestException as e:
            logger.debug("Error fetching zones: %s", e)
            return None

    def _find_txt_record(
        self, zone_id: int, record_name: str, record_content: str
    ) -> Optional[dict[str, Any]]:
        """Find a specific TXT record in a zone.

        Args:
            zone_id: The zone ID to search in.
            record_name: The record name to find.
            record_content: The record content to match.

        Returns:
            The record dict if found, None otherwise.
        """
        url = f"{self.api_url}/api/{self.api_version}/zones/{zone_id}/records"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            records = response.json()

            # Handle both list and dict response formats
            if isinstance(records, dict) and "data" in records:
                records = records["data"]

            for record in records:
                if record.get("type") != "TXT":
                    continue

                # Compare record name (with or without a trailing dot)
                stored_name = record.get("name", "").rstrip(".")
                target_name = record_name.rstrip(".")
                if stored_name != target_name:
                    continue

                # Compare content (may be quoted in API response)
                stored_content = record.get("content", "").strip('"')
                if stored_content == record_content:
                    return record

            return None

        except requests.exceptions.RequestException as e:
            logger.debug("Error fetching records: %s", e)
            return None

    @staticmethod
    def _get_error_hint(response: Optional[requests.Response]) -> str:
        """Extract error hint from API response.

        Args:
            response: The HTTP response object.

        Returns:
            A hint string for the error, or empty string.
        """
        if response is None:
            return ""

        hint = ""
        try:
            error_data = response.json()
            if isinstance(error_data, dict):
                message = error_data.get("message") or error_data.get("error")
                if message:
                    hint = f" ({message})"
        except (ValueError, KeyError):
            pass

        # Add specific hints based on the status code
        if response.status_code == 401:
            hint = hint or " (Is your API key correct?)"
        elif response.status_code == 403:
            hint = hint or " (Does your API key have sufficient permissions?)"
        elif response.status_code == 404:
            hint = hint or " (Zone or record not found)"

        return hint
