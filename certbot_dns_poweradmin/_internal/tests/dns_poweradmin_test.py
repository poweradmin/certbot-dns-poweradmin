"""Tests for certbot_dns_poweradmin._internal.dns_poweradmin."""

from __future__ import annotations

import unittest
from unittest import mock

import requests_mock
from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_dns_poweradmin import Authenticator
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


class PowerAdminClientTest(unittest.TestCase):
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

    def test_add_txt_record_already_exists(self) -> None:
        """Test adding a TXT record that already exists."""
        self._register_zones_response()
        self._register_records_response(
            records=[
                {
                    "id": 50,
                    "name": self.record_name,
                    "type": "TXT",
                    "content": self.record_content,
                }
            ]
        )

        # Should not raise, should just return (idempotent)
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        # Verify no POST request was made
        history = self.adapter.request_history
        post_requests = [r for r in history if r.method == "POST"]
        self.assertEqual(len(post_requests), 0)

    def test_add_txt_record_zone_not_found(self) -> None:
        """Test adding a TXT record when a zone is not found."""
        self._register_zones_response(zones=[])

        with self.assertRaises(errors.PluginError) as context:
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )

        self.assertIn("Unable to find", str(context.exception))

    def test_del_txt_record(self) -> None:
        """Test deleting a TXT record."""
        self._register_zones_response()
        self._register_records_response(
            records=[
                {
                    "id": 100,
                    "name": self.record_name,
                    "type": "TXT",
                    "content": self.record_content,
                }
            ]
        )
        self._register_delete_record_response()

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        # Verify the DELETE request was made
        history = self.adapter.request_history
        delete_requests = [r for r in history if r.method == "DELETE"]
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

    def test_find_zone_with_trailing_dot(self) -> None:
        """Test finding a zone when API returns name with trailing dot."""
        self._register_zones_response(zones=[{"id": 1, "name": "example.com."}])
        self._register_records_response()
        self._register_add_record_response()

        # Should find the zone despite trailing dot
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

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

        with self.assertRaises(errors.PluginError) as context:
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl
            )

        self.assertIn("401", str(context.exception))

    def test_headers_contain_api_key(self) -> None:
        """Test that requests contain the API key header."""
        self._register_zones_response()

        # Trigger a request
        self.client._get_zone_id_by_name("example.com")

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
    unittest.main()
