"""Tests for certbot_dns_poweradmin._internal.dns_poweradmin."""

from __future__ import annotations

from typing import Any
from unittest import TestCase, main, mock

import requests
import requests_mock
from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_dns_poweradmin import Authenticator
from certbot_dns_poweradmin._internal import dns_poweradmin
from certbot_dns_poweradmin._internal.dns_poweradmin import _PowerAdminClient

API_URL = "https://poweradmin.example.com"
API_KEY = "test-api-key"
API_VERSION = "v2"


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    """Tests for Authenticator class."""

    def setUp(self) -> None:
        super().setUp()

        path = os.path.join(self.tempdir, "credentials.ini")
        dns_test_common.write(
            {
                "poweradmin_api_url": API_URL,
                "poweradmin_api_key": API_KEY,
                "poweradmin_api_version": API_VERSION,
            },
            path,
        )

        self.config = mock.MagicMock(
            poweradmin_credentials=path,
            poweradmin_propagation_seconds=0,
        )
        self.auth = Authenticator(self.config, "poweradmin")

        self.mock_client = mock.MagicMock()
        self.auth._get_poweradmin_client = mock.MagicMock(return_value=self.mock_client)

    @test_util.patch_display_util()
    def test_perform(self, _: mock.MagicMock) -> None:
        self.auth.perform([self.achall])
        expected = [
            mock.call.add_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY, mock.ANY)
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    @test_util.patch_display_util()
    def test_cleanup(self, _: mock.MagicMock) -> None:
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])
        expected = [mock.call.del_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_client_is_cached(self) -> None:
        """The API client (and its session) is created once and reused."""
        auth = Authenticator(self.config, "poweradmin")
        auth.credentials = mock.MagicMock(
            conf=lambda key: {
                "api-url": API_URL,
                "api-key": API_KEY,
                "api-version": API_VERSION,
            }[key]
        )
        self.assertIs(auth._get_poweradmin_client(), auth._get_poweradmin_client())

    def test_missing_credentials_raise_plugin_error(self) -> None:
        """Missing URL/key raise an explicit error (asserts would vanish under -O)."""
        auth = Authenticator(self.config, "poweradmin")
        auth.credentials = mock.MagicMock(conf=lambda key: None)
        with self.assertRaises(errors.PluginError):
            auth._get_poweradmin_client()

    def _validate_with_url(self, api_url: str) -> None:
        auth = Authenticator(self.config, "poweradmin")
        credentials = mock.MagicMock(
            conf=lambda key: {
                "api-url": api_url,
                "api-key": API_KEY,
                "api-version": API_VERSION,
            }[key]
        )
        auth._validate_credentials(credentials)

    def test_api_url_without_scheme_is_rejected(self) -> None:
        """A URL without http(s):// fails at setup, not with a confusing runtime error."""
        with self.assertRaises(errors.PluginError) as context:
            self._validate_with_url("poweradmin.example.com")
        self.assertIn("http", str(context.exception))

    def test_api_url_with_api_path_is_rejected(self) -> None:
        """A URL already ending in /api (or /api/vN) would 404 on every call."""
        for url in (
            f"{API_URL}/api",
            f"{API_URL}/api/",
            f"{API_URL}/api/v1",
            f"{API_URL}/api/v2",
        ):
            with self.subTest(url=url), self.assertRaises(errors.PluginError) as context:
                self._validate_with_url(url)
            self.assertIn("/api", str(context.exception))

    def test_api_url_with_base_path_is_accepted(self) -> None:
        """An installation mounted under a path (not /api) validates fine."""
        self._validate_with_url(f"{API_URL}/poweradmin")


class PowerAdminClientTest(TestCase):
    """Tests for _PowerAdminClient class."""

    record_name = "_acme-challenge.example.com"
    record_content = "validation-token"
    record_ttl = 120

    def setUp(self) -> None:
        self.adapter = requests_mock.Adapter()
        self.client = _PowerAdminClient(API_URL, API_KEY, API_VERSION)
        self.client.session.mount("https://", self.adapter)

    def _register_zones_response(
        self, zones: list[dict] | None = None, api_v2_format: bool = False
    ) -> None:
        """Register a mock response for zones endpoint.

        Args:
            zones: List of zone dicts.
            api_v2_format: If True, wrap in {"data": {"zones": [...]}},
                           otherwise use {"data": [...]}.
        """
        if zones is None:
            zones = [{"id": 1, "name": "example.com"}]

        data: dict[str, list[dict[str, str | int]]] | list[dict[str, str | int]] = (
            {"zones": zones} if api_v2_format else zones
        )
        response = {"data": data}

        self.adapter.register_uri(
            "GET",
            f"{API_URL}/api/{API_VERSION}/zones",
            json=response,
        )

    def _register_records_response(
        self, zone_id: int = 1, records: list[dict] | None = None
    ) -> None:
        """Register a mock response for records endpoint."""
        if records is None:
            records = []
        self.adapter.register_uri(
            "GET",
            f"{API_URL}/api/{API_VERSION}/zones/{zone_id}/records",
            json={"data": records},
        )

    def _register_add_record_response(self, zone_id: int = 1, status_code: int = 201) -> None:
        """Register a mock response for adding a record."""
        self.adapter.register_uri(
            "POST",
            f"{API_URL}/api/{API_VERSION}/zones/{zone_id}/records",
            status_code=status_code,
            json={"id": 100, "name": self.record_name, "type": "TXT"},
        )

    def _register_delete_record_response(
        self, zone_id: int = 1, record_id: int = 100, status_code: int = 204
    ) -> None:
        """Register a mock response for deleting a record."""
        self.adapter.register_uri(
            "DELETE",
            f"{API_URL}/api/{API_VERSION}/zones/{zone_id}/records/{record_id}",
            status_code=status_code,
        )

    def _register_zones_failure(self, **kwargs: Any) -> None:
        """Register a failing response for the zones endpoint."""
        self.adapter.register_uri("GET", f"{API_URL}/api/{API_VERSION}/zones", **kwargs)

    def _register_existing_record(self, content: str, record_id: int | str = 100) -> None:
        """Register a records listing containing a single TXT record."""
        self._register_records_response(
            records=[{"id": record_id, "name": self.record_name, "type": "TXT", "content": content}]
        )

    def _assert_add_raises(self) -> str:
        """Run add_txt_record, assert it raises PluginError, return the message."""
        with self.assertRaises(errors.PluginError) as context:
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )
        return str(context.exception)

    def test_add_txt_record(self) -> None:
        """Test adding a TXT record."""
        self._register_zones_response()
        self._register_records_response()
        self._register_add_record_response()

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        # Verify the POST request was made
        history = self.adapter.request_history
        post_request = [r for r in history if r.method == "POST"][0]
        self.assertIn("TXT", post_request.text)

    def test_add_txt_record_sends_quoted_content(self) -> None:
        """TXT content is quoted in the POST body (required by API v1)."""
        self._register_zones_response()
        self._register_records_response()
        self._register_add_record_response()

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        post_request = [r for r in self.adapter.request_history if r.method == "POST"][0]
        self.assertEqual(post_request.json()["content"], f'"{self.record_content}"')

    def test_add_txt_record_does_not_double_quote(self) -> None:
        """Already-quoted content is not quoted again."""
        self._register_zones_response()
        self._register_records_response()
        self._register_add_record_response()

        quoted = f'"{self.record_content}"'
        self.client.add_txt_record(DOMAIN, self.record_name, quoted, self.record_ttl)

        post_request = [r for r in self.adapter.request_history if r.method == "POST"][0]
        self.assertEqual(post_request.json()["content"], quoted)

    def test_add_txt_record_already_exists_quoted_in_api(self) -> None:
        """Idempotency check matches when the API returns quoted content (v1 format)."""
        self._register_zones_response()
        self._register_existing_record(f'"{self.record_content}"', record_id=50)

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        post_requests = [r for r in self.adapter.request_history if r.method == "POST"]
        self.assertEqual(len(post_requests), 0)

    def test_del_txt_record_quoted_in_api(self) -> None:
        """Delete finds the record when the API returns quoted content (v1 format)."""
        self._register_zones_response()
        self._register_existing_record(f'"{self.record_content}"')
        self._register_delete_record_response()

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        delete_requests = [r for r in self.adapter.request_history if r.method == "DELETE"]
        self.assertEqual(len(delete_requests), 1)

    def test_add_txt_record_already_exists(self) -> None:
        """Test adding a TXT record that already exists."""
        self._register_zones_response()
        self._register_existing_record(self.record_content, record_id=50)

        # Should not raise, should just return (idempotent)
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        # Verify no POST request was made
        post_requests = [r for r in self.adapter.request_history if r.method == "POST"]
        self.assertEqual(len(post_requests), 0)

    def test_add_txt_record_zone_not_found(self) -> None:
        """Test adding a TXT record when a zone is not found."""
        self._register_zones_response(zones=[])

        self.assertIn("Unable to find", self._assert_add_raises())

    def test_del_txt_record(self) -> None:
        """Test deleting a TXT record."""
        self._register_zones_response()
        self._register_existing_record(self.record_content)
        self._register_delete_record_response()

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        # Verify the DELETE request was made
        delete_requests = [r for r in self.adapter.request_history if r.method == "DELETE"]
        self.assertEqual(len(delete_requests), 1)

    def test_del_txt_record_not_found(self) -> None:
        """Test deleting a TXT record that doesn't exist."""
        self._register_zones_response()
        self._register_records_response(records=[])

        # Should not raise (graceful cleanup)
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_zone_not_found(self) -> None:
        """Test deleting when a zone is not found."""
        self._register_zones_response(zones=[])

        # Should not raise (graceful cleanup)
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_find_zone_case_insensitive(self) -> None:
        """A mixed-case zone name in PowerAdmin still matches (DNS is case-insensitive)."""
        self._register_zones_response(zones=[{"id": 1, "name": "Example.COM."}])
        self._register_records_response()
        self._register_add_record_response()

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        post_requests = [r for r in self.adapter.request_history if r.method == "POST"]
        self.assertEqual(len(post_requests), 1)

    def test_error_hint_with_non_string_message_falls_back(self) -> None:
        """A dict-valued error field falls back to the status-code hint."""
        self._register_zones_response()
        self._register_records_response()
        self.adapter.register_uri(
            "POST",
            f"{API_URL}/api/{API_VERSION}/zones/1/records",
            status_code=500,
            json={"error": {"code": 1}},
        )

        message = self._assert_add_raises()
        self.assertIn("PowerAdmin API server error", message)
        self.assertNotIn("code", message)

    def test_find_zone_with_trailing_dot(self) -> None:
        """Test finding a zone when API returns name with trailing dot."""
        self._register_zones_response(zones=[{"id": 1, "name": "example.com."}])
        self._register_records_response()
        self._register_add_record_response()

        # Should find the zone despite trailing dot
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_find_zone_with_absolute_domain(self) -> None:
        """An absolute domain (trailing dot) still matches a dot-less stored zone."""
        self._register_zones_response()
        self._register_records_response()
        self._register_add_record_response()

        self.client.add_txt_record(
            DOMAIN + ".", self.record_name, self.record_content, self.record_ttl
        )

        post_requests = [r for r in self.adapter.request_history if r.method == "POST"]
        self.assertEqual(len(post_requests), 1)

    def test_api_error_handling(self) -> None:
        """Test API error handling."""
        self._register_zones_response()
        self._register_records_response()
        self.adapter.register_uri(
            "POST",
            f"{API_URL}/api/{API_VERSION}/zones/1/records",
            status_code=401,
            json={"message": "Invalid API key"},
        )

        self.assertIn("401", self._assert_add_raises())

    def test_add_txt_record_surfaces_api_message(self) -> None:
        """A non-2xx on create surfaces the API message field in the error."""
        self._register_zones_response()
        self._register_records_response()
        self.adapter.register_uri(
            "POST",
            f"{API_URL}/api/{API_VERSION}/zones/1/records",
            status_code=500,
            json={"message": "Failed to create record"},
        )

        self.assertIn("Failed to create record", self._assert_add_raises())

    def test_zone_lookup_server_error_raises_plugin_error(self) -> None:
        """A server error while listing zones surfaces as itself, not as 'zone not found'."""
        self._register_zones_failure(status_code=500, json={"message": "Internal error"})

        message = self._assert_add_raises()
        self.assertIn("Internal error", message)
        self.assertNotIn("Unable to find", message)

    def test_zone_lookup_auth_error_mentions_api_key(self) -> None:
        """A 401 while listing zones points at the API key, not at zone config."""
        self._register_zones_failure(status_code=401, json={})

        message = self._assert_add_raises()
        self.assertIn("Is your API key correct?", message)
        self.assertNotIn("Unable to find", message)

    def test_zone_lookup_connection_error_raises_plugin_error(self) -> None:
        """Connection-level failures surface as communication errors, not 'zone not found'."""
        for exc in (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
            with self.subTest(exc=exc.__name__):
                self._register_zones_failure(exc=exc)
                self.assertIn("Error communicating with PowerAdmin API", self._assert_add_raises())

    def test_requests_use_timeout(self) -> None:
        """Every API request carries a timeout so renewals cannot hang forever."""
        self._register_zones_response()
        self._register_records_response()
        self._register_add_record_response()
        self._register_delete_record_response()

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)
        self._register_existing_record(self.record_content)
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        for request in self.adapter.request_history:
            self.assertEqual(request.timeout, dns_poweradmin.API_TIMEOUT, request.url)

    def test_headers_contain_api_key(self) -> None:
        """Test that requests contain the API key header."""
        self._register_zones_response()

        # Trigger a request
        self.client._find_zone_id(DOMAIN)

        # Verify headers
        history = self.adapter.request_history
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].headers["X-API-Key"], API_KEY)

    def test_zones_api_v2_nested_format(self) -> None:
        """Test handling of API v2 nested zones response format."""
        self._register_zones_response(api_v2_format=True)
        self._register_records_response()
        self._register_add_record_response()

        # Should find the zone with nested format
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        # Verify the POST request was made
        history = self.adapter.request_history
        post_requests = [r for r in history if r.method == "POST"]
        self.assertEqual(len(post_requests), 1)

    def test_records_api_v2_nested_format(self) -> None:
        """Test handling of API v2 nested records response format."""
        self._register_zones_response(api_v2_format=True)
        self.adapter.register_uri(
            "GET",
            f"{API_URL}/api/{API_VERSION}/zones/1/records",
            json={
                "data": {
                    "records": [
                        {
                            "id": 100,
                            "name": self.record_name,
                            "type": "TXT",
                            "content": self.record_content,
                        }
                    ]
                }
            },
        )
        self._register_delete_record_response()

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        # Verify the DELETE request was made (record was found in nested format)
        history = self.adapter.request_history
        delete_requests = [r for r in history if r.method == "DELETE"]
        self.assertEqual(len(delete_requests), 1)

    def test_zone_with_null_name_is_skipped(self) -> None:
        """A zone entry with a null name is skipped instead of crashing."""
        self._register_zones_response(
            zones=[{"id": 2, "name": None}, {"id": 1, "name": "example.com"}]
        )
        self._register_records_response()
        self._register_add_record_response()

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_unexpected_zones_envelope_raises_plugin_error(self) -> None:
        """A data envelope without a zones list raises PluginError, not AttributeError."""
        self._register_zones_failure(json={"data": {"message": "something", "success": True}})

        self.assertIn("Unexpected response format", self._assert_add_raises())

    def test_non_list_payload_raises_plugin_error(self) -> None:
        """A completely unexpected payload type raises PluginError."""
        self._register_zones_failure(json="unexpected")

        self._assert_add_raises()

    def test_record_with_null_content_is_skipped(self) -> None:
        """A record entry with null content is skipped instead of crashing."""
        self._register_zones_response()
        self._register_records_response(
            records=[
                {"id": 5, "name": self.record_name, "type": "TXT", "content": None},
                {"id": 6, "name": None, "type": "TXT", "content": self.record_content},
            ]
        )
        self._register_add_record_response()

        # Neither malformed record matches, so a new record is created
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        post_requests = [r for r in self.adapter.request_history if r.method == "POST"]
        self.assertEqual(len(post_requests), 1)

    def test_cleanup_swallows_api_failures(self) -> None:
        """Cleanup never raises, whatever the API failure mode."""
        scenarios: list[tuple[str, dict]] = [
            ("auth error", {"status_code": 401, "json": {}}),
            ("timeout", {"exc": requests.exceptions.ConnectTimeout}),
            ("malformed zone entry", {"json": {"data": {"zones": [{"id": 1, "name": None}]}}}),
            ("unexpected envelope", {"json": {"data": {"message": "something"}}}),
        ]
        for name, kwargs in scenarios:
            with self.subTest(scenario=name):
                self._register_zones_failure(**kwargs)
                self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_post_redirect_raises_instead_of_silent_success(self) -> None:
        """A redirected create (e.g. http->https) fails loudly.

        requests would replay the POST as a GET, which returns 200 (the
        records listing) and would make the plugin report success without
        ever creating the record.
        """
        self._register_zones_response()
        self._register_records_response()
        self.adapter.register_uri(
            "POST",
            f"{API_URL}/api/{API_VERSION}/zones/1/records",
            status_code=301,
            headers={"Location": f"{API_URL}/api/{API_VERSION}/zones/1/records"},
        )

        message = self._assert_add_raises()
        self.assertIn("redirected", message)
        self.assertIn("dns_poweradmin_api_url", message)

    def test_zone_listing_redirect_raises_plugin_error(self) -> None:
        """A redirect on the zones listing surfaces as itself, not 'zone not found'."""
        self._register_zones_failure(status_code=302, headers={"Location": "https://elsewhere"})

        message = self._assert_add_raises()
        self.assertIn("redirected", message)
        self.assertNotIn("Unable to find", message)

    def test_zone_with_missing_id_falls_through_to_valid_entry(self) -> None:
        """A matching zone without an ID is skipped, not reported as 'zone not found'."""
        self._register_zones_response(
            zones=[{"name": "example.com"}, {"id": 1, "name": "example.com"}]
        )
        self._register_records_response()
        self._register_add_record_response()

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        post_requests = [r for r in self.adapter.request_history if r.method == "POST"]
        self.assertEqual(len(post_requests), 1)

    def test_disabled_record_is_not_treated_as_existing(self) -> None:
        """A disabled record with matching content does not satisfy the challenge."""
        self._register_zones_response()
        self._register_records_response(
            records=[
                {
                    "id": 5,
                    "name": self.record_name,
                    "type": "TXT",
                    "content": self.record_content,
                    "disabled": True,
                }
            ]
        )
        self._register_add_record_response()

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        post_requests = [r for r in self.adapter.request_history if r.method == "POST"]
        self.assertEqual(len(post_requests), 1)

    def test_del_ignores_disabled_record(self) -> None:
        """Cleanup does not delete a disabled record it did not create."""
        self._register_zones_response()
        self._register_records_response(
            records=[
                {
                    "id": 5,
                    "name": self.record_name,
                    "type": "TXT",
                    "content": self.record_content,
                    "disabled": True,
                }
            ]
        )

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        delete_requests = [r for r in self.adapter.request_history if r.method == "DELETE"]
        self.assertEqual(len(delete_requests), 0)

    def test_string_record_id_is_url_encoded(self) -> None:
        """A string record ID with reserved characters is quoted in the DELETE URL."""
        self._register_zones_response()
        self._register_existing_record(self.record_content, record_id="rec/1?x")
        self.adapter.register_uri(
            "DELETE",
            f"{API_URL}/api/{API_VERSION}/zones/1/records/rec%2F1%3Fx",
            status_code=204,
        )

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        delete_requests = [r for r in self.adapter.request_history if r.method == "DELETE"]
        self.assertEqual(len(delete_requests), 1)
        self.assertIn("rec%2F1%3Fx", delete_requests[0].url)

    def test_close_closes_session(self) -> None:
        """close() shuts down the underlying HTTP session."""
        client = _PowerAdminClient(API_URL, API_KEY, API_VERSION)
        client.session = mock.MagicMock()
        client.close()
        client.session.close.assert_called_once()

    def test_zones_api_v1_flat_format(self) -> None:
        """Test handling of API v1 flat zones response format."""
        self._register_zones_response(api_v2_format=False)
        self._register_records_response()
        self._register_add_record_response()

        # Should find the zone with flat format
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        # Verify the POST request was made
        history = self.adapter.request_history
        post_requests = [r for r in history if r.method == "POST"]
        self.assertEqual(len(post_requests), 1)


if __name__ == "__main__":
    main()
