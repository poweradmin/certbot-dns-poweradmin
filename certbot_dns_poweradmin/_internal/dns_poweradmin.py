"""DNS Authenticator for PowerAdmin."""

from __future__ import annotations

import contextlib
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlparse

import requests
from certbot import achallenges, errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

DEFAULT_API_VERSION = "v2"
SUPPORTED_API_VERSIONS = ("v1", "v2")
API_TIMEOUT = 30  # seconds; keeps unattended renewals from hanging on a stalled API
MAX_ERROR_HINT_LENGTH = 200  # characters; keeps API error bodies from flooding the error

# A quoted TXT string whose interior is properly escaped: any embedded
# double quote or backslash must be preceded by a backslash.
_QUOTED_TXT_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for PowerAdmin.

    This Authenticator uses the PowerAdmin API to fulfill a dns-01 challenge.
    """

    description = (
        "Obtain certificates using a DNS TXT record (if you are using PowerAdmin for DNS)."
    )
    ttl = 120

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: CredentialsConfiguration | None = None
        self._client: _PowerAdminClient | None = None

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
        self._validate_api_url(api_url)
        if not api_key:
            raise errors.PluginError("PowerAdmin API key is required (dns_poweradmin_api_key)")
        # requests refuses a header value with leading whitespace or CR/LF
        # by raising an error that echoes the full value, which would leak
        # the key into the terminal and letsencrypt.log. Reject it here,
        # without echoing it. Trailing whitespace would pass requests but
        # silently break authentication, so it is rejected too.
        if api_key != api_key.strip() or re.search(r"[\r\n]", api_key):
            raise errors.PluginError(
                "PowerAdmin API key must not contain leading/trailing "
                "whitespace or line breaks (check dns_poweradmin_api_key "
                "in the credentials file)"
            )
        if api_version and api_version.lower() not in SUPPORTED_API_VERSIONS:
            raise errors.PluginError(
                f"Invalid API version: {api_version}. "
                f"Supported versions: {', '.join(SUPPORTED_API_VERSIONS)}"
            )

    @staticmethod
    def _validate_api_url(api_url: str) -> None:
        parsed = urlparse(api_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise errors.PluginError(
                f"PowerAdmin API URL must start with http:// or https:// (got: {api_url})"
            )
        # The client appends /api/<version>/... to the URL, so a query string
        # or fragment would corrupt every request URL it builds.
        if parsed.query or parsed.fragment:
            raise errors.PluginError(
                f"PowerAdmin API URL must not contain a query string or fragment (got: {api_url})"
            )
        # The client appends /api/<version>/... itself; a URL that already
        # ends in /api (or /api/v1, /api/v2) would silently 404 on every call.
        path = parsed.path.rstrip("/")
        if path.endswith(("/api", "/api/v1", "/api/v2")):
            raise errors.PluginError(
                f"PowerAdmin API URL must be the base URL of your installation, "
                f"without the /api path (got: {api_url})"
            )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_poweradmin_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_poweradmin_client().del_txt_record(domain, validation_name, validation)

    def cleanup(self, achalls: list[achallenges.AnnotatedChallenge]) -> None:
        try:
            super().cleanup(achalls)
        finally:
            # Cleanup is the last API interaction; close the session instead
            # of relying on __del__. A later call recreates the client.
            if self._client is not None:
                self._client.close()
                self._client = None

    def _get_poweradmin_client(self) -> _PowerAdminClient:
        if self.credentials is None:
            raise errors.PluginError("Credentials not configured")

        if self._client is None:
            api_url = self.credentials.conf("api-url")
            api_key = self.credentials.conf("api-key")
            api_version = (self.credentials.conf("api-version") or DEFAULT_API_VERSION).lower()

            # Already checked in _validate_credentials; explicit so `python -O` stays safe
            if not api_url or not api_key:
                raise errors.PluginError("PowerAdmin API URL and API key are required")

            self._client = _PowerAdminClient(
                api_url=api_url,
                api_key=api_key,
                api_version=api_version,
            )
        return self._client


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

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self.session.close()

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()

    def _endpoint(self, *segments: object) -> str:
        """Build an API URL, percent-encoding each path segment.

        Zone and record IDs may be strings (depending on the PowerAdmin
        backend), so they cannot be interpolated into the path verbatim.
        """
        path = "/".join(quote(str(segment), safe="") for segment in segments)
        return f"{self.api_url}/api/{self.api_version}/{path}"

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
        zone_id, _zone_name = self._find_zone_id(domain)
        if zone_id is None:
            raise errors.PluginError(f"Unable to find a PowerAdmin zone for {domain}")

        # Check if a record already exists (idempotent)
        existing_record = self._find_txt_record(zone_id, record_name, record_content)
        if existing_record is not None:
            logger.debug("TXT record already exists, skipping creation")
            return

        # Create the TXT record. Content must be quoted: API v1 rejects unquoted
        # TXT content, while v2 accepts either and quotes server-side.
        record_data = {
            "name": record_name,
            "type": "TXT",
            "content": self._quote_txt_content(record_content),
            "ttl": record_ttl,
        }

        url = self._endpoint("zones", zone_id, "records")
        self._request("POST", url, json=record_data)
        logger.debug("Successfully added TXT record for %s", record_name)

    def del_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """Delete a TXT record using the PowerAdmin API.

        Args:
            domain: The domain to use for finding the zone.
            record_name: The record name (FQDN).
            record_content: The record content (validation token).
        """
        try:
            zone_id, _zone_name = self._find_zone_id(domain)
            if zone_id is None:
                logger.debug("Unable to find zone for %s during cleanup", domain)
                return

            record = self._find_txt_record(zone_id, record_name, record_content)
            if record is None:
                logger.debug("TXT record not found for %s during cleanup", record_name)
                return

            record_id = record.get("id")
            # bool is excluded explicitly: it passes isinstance(..., int)
            # but would produce URLs like records/True.
            if isinstance(record_id, bool) or not isinstance(record_id, (int, str)):
                logger.warning("Record found but has no usable ID, cannot delete")
                return

            url = self._endpoint("zones", zone_id, "records", record_id)
            self._request("DELETE", url)
            logger.debug("Successfully deleted TXT record for %s", record_name)

        except errors.PluginError as e:
            # Cleanup is best-effort: _request/_fetch_items translate all API
            # failures into PluginError, so this catches every failure mode.
            logger.warning("Error deleting TXT record during cleanup: %s", e)

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Send an API request, translating failures into PluginError.

        Redirects are not followed: requests would replay a redirected POST
        as a GET (e.g. on an http:// URL that redirects to https://), turning
        a failed record creation into a silent success.

        Raises:
            errors.PluginError: On redirects, HTTP error statuses (with a
                hint extracted from the response) or connection-level
                failures.
        """
        try:
            response = self.session.request(
                method, url, timeout=API_TIMEOUT, allow_redirects=False, **kwargs
            )
            if response.status_code == 304:
                # Not a redirect: the plugin sends no conditional headers,
                # so a 304 means a broken proxy or server. A 304 has no
                # body, so treating it as success would hide a failure.
                raise errors.PluginError(
                    f"PowerAdmin API returned an unexpected 304 Not Modified "
                    f"for {method} {url}. This usually indicates a broken "
                    "proxy or cache in front of PowerAdmin."
                )
            if 300 <= response.status_code < 400:
                # The Location header is server-controlled text, same as a
                # JSON error body: sanitize before echoing it.
                location = (
                    self._sanitize_server_text(response.headers.get("Location", ""))
                    or "<no Location header>"
                )
                raise errors.PluginError(
                    f"PowerAdmin API redirected {method} {url} to {location}. "
                    "Set dns_poweradmin_api_url to the final URL "
                    "(e.g. use https:// directly)."
                )
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            hint = self._get_error_hint(e.response)
            # str(e) embeds the server's status-line reason phrase, which
            # can carry the same control characters as a JSON error body.
            raise errors.PluginError(
                f"PowerAdmin API error: {self._sanitize_server_text(str(e))}{hint}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise errors.PluginError(f"Error communicating with PowerAdmin API: {e}") from e

    def _fetch_items(self, url: str, key: str) -> list[dict[str, Any]]:
        """GET a listing endpoint and unwrap the response envelope.

        Handles both the v1 format ({"data": [...]}) and the v2 format
        ({"data": {key: [...]}}), skipping any malformed (non-dict) entries.

        Raises:
            errors.PluginError: On API failures or if the payload has an
                unexpected shape. Auth and connectivity problems must surface
                as themselves, not be mistaken for "zone not found".
        """
        response = self._request("GET", url)
        try:
            items: Any = response.json()
        except requests.exceptions.JSONDecodeError as e:
            raise errors.PluginError(
                f"Unexpected response format from PowerAdmin API: {url}"
            ) from e
        if isinstance(items, dict) and "data" in items:
            items = items["data"]
            if isinstance(items, dict) and key in items:
                items = items[key]
        if not isinstance(items, list):
            raise errors.PluginError(f"Unexpected response format from PowerAdmin API: {url}")
        return [item for item in items if isinstance(item, dict)]

    def _find_zone_id(self, domain: str) -> tuple[int | str | None, str | None]:
        """Find the zone ID for a given domain.

        Args:
            domain: The domain being validated.

        Returns:
            Tuple of (zone_id, zone_name) or (None, None) if not found.
        """
        zones = self._fetch_items(self._endpoint("zones"), "zones")

        for zone_name in dns_common.base_domain_name_guesses(domain):
            for zone in zones:
                stored_name = zone.get("name")
                if not isinstance(stored_name, str) or not self._names_equal(
                    stored_name, zone_name
                ):
                    continue
                zone_id = zone.get("id")
                # bool is excluded explicitly: it passes isinstance(..., int)
                # but would produce URLs like zones/True/records.
                if isinstance(zone_id, bool) or not isinstance(zone_id, (int, str)):
                    logger.warning("Zone %s matched but has no usable ID, skipping", zone_name)
                    continue
                logger.debug("Found zone %s with ID %s", zone_name, zone_id)
                return zone_id, zone_name

        return None, None

    def _find_txt_record(
        self, zone_id: int | str, record_name: str, record_content: str
    ) -> dict[str, Any] | None:
        """Find a specific TXT record in a zone.

        Disabled records are ignored: this plugin only creates enabled
        records, and a disabled record does not serve the challenge, so
        treating one as "already exists" would break validation.

        Args:
            zone_id: The zone ID to search in.
            record_name: The record name to find.
            record_content: The record content to match.

        Returns:
            The record dict if found, None otherwise.
        """
        records = self._fetch_items(self._endpoint("zones", zone_id, "records"), "records")

        for record in records:
            if record.get("type") != "TXT":
                continue

            if record.get("disabled"):
                logger.debug("Ignoring disabled TXT record for %s", record.get("name"))
                continue

            stored_name = record.get("name")
            stored_content = record.get("content")
            if not isinstance(stored_name, str) or not isinstance(stored_content, str):
                continue

            if not self._names_equal(stored_name, record_name):
                continue

            # Content may be quoted in the API response (v1) or by the caller
            if self._unquote_txt_content(stored_content) == self._unquote_txt_content(
                record_content
            ):
                return record

        return None

    @staticmethod
    def _names_equal(name_a: str, name_b: str) -> bool:
        """Compare DNS names case-insensitively, ignoring any trailing dot."""
        return name_a.rstrip(".").lower() == name_b.rstrip(".").lower()

    @staticmethod
    def _quote_txt_content(content: str) -> str:
        """Wrap TXT record content in double quotes if not already quoted.

        Content counts as already quoted only if its interior is properly
        escaped; anything else (e.g. 'a"b"c"') is escaped and wrapped as a
        whole. ACME validation tokens are base64url so certbot never
        produces content needing escapes, but the client methods accept
        arbitrary content.
        """
        if _QUOTED_TXT_RE.fullmatch(content):
            return content
        escaped = content.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    @staticmethod
    def _unquote_txt_content(content: str) -> str:
        """Undo the quoting and escaping added by _quote_txt_content, if present."""
        if _QUOTED_TXT_RE.fullmatch(content):
            return re.sub(r"\\(.)", r"\1", content[1:-1])
        return content

    @staticmethod
    def _sanitize_server_text(text: str) -> str:
        """Neutralize server-supplied text before echoing it to the terminal.

        Strips control characters (newlines, ANSI escapes) a broken or
        hostile server could embed, and truncates so a huge value cannot
        flood the error message.
        """
        text = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", text).strip()
        if len(text) > MAX_ERROR_HINT_LENGTH:
            text = text[:MAX_ERROR_HINT_LENGTH] + "..."
        return text

    @staticmethod
    def _get_error_hint(response: requests.Response | None) -> str:
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
                if isinstance(message, str):
                    message = _PowerAdminClient._sanitize_server_text(message)
                    if message:
                        hint = f" ({message})"
        except (ValueError, KeyError):
            # Malformed or non-JSON body; fall back to status-code hints below.
            pass

        # Add specific hints based on the status code
        if response.status_code == 400:
            hint = hint or " (Invalid request)"
        elif response.status_code == 401:
            hint = hint or " (Is your API key correct?)"
        elif response.status_code == 403:
            hint = hint or " (Does your API key have sufficient permissions?)"
        elif response.status_code == 404:
            hint = hint or " (Zone or record not found)"
        elif response.status_code == 409:
            hint = hint or " (Conflicts with an existing record or zone)"
        elif response.status_code >= 500:
            hint = hint or " (PowerAdmin API server error)"

        return hint
