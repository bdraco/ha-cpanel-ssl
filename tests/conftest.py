"""Fixtures for cPanel SSL tests."""

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from aiocpanel import Certificate, DynamicDnsRecord
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cpanel_ssl.const import (
    CONF_DOMAIN,
    CONF_DYNAMIC_DNS,
    CONF_UPDATE_INTERVAL,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
)
from homeassistant.const import (
    CONF_API_TOKEN,
    CONF_HOST,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant

HOST = "server.example.com"
FQDN = "home.example.com"
NOT_AFTER = datetime(2027, 1, 1, tzinfo=UTC)
RECORD = DynamicDnsRecord(
    id="abcdefghijklmnopqrstuvwxyzabcdef",
    domain=FQDN,
    webcall_url=f"https://{HOST}:2083/cpanelwebcall/abcdefghijklmnopqrstuvwxyzabcdef",
)

ENTRY_DATA = {
    CONF_HOST: HOST,
    CONF_PORT: 2083,
    CONF_USERNAME: "user",
    CONF_API_TOKEN: "token",
    CONF_VERIFY_SSL: True,
    CONF_DOMAIN: FQDN,
}
DDNS_OPTIONS = {CONF_UPDATE_INTERVAL: DEFAULT_UPDATE_INTERVAL, CONF_DYNAMIC_DNS: True}


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Enable custom integrations in every test."""


def make_certificate(not_after: datetime = NOT_AFTER) -> Certificate:
    """Return a self signed certificate as cPanel would serve it."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, FQDN)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - timedelta(days=90))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return Certificate(
        crt=cert.public_bytes(serialization.Encoding.PEM).decode(),
        key=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        cab=None,
    )


@pytest.fixture
def certificate() -> Certificate:
    """Return the certificate the mocked cPanel serves."""
    return make_certificate()


@pytest.fixture
def mock_cpanel_client(certificate: Certificate) -> Generator[AsyncMock]:
    """Mock the cPanel client used by setup and the config flow."""
    with patch(
        "custom_components.cpanel_ssl.coordinator.CpanelClient", autospec=True
    ) as client_class:
        client = client_class.return_value
        client.fetch_certificate.return_value = certificate
        client.ensure_dynamic_dns.return_value = RECORD
        client.call_webcall.return_value = "ipv4: 203.0.113.7"
        yield client


@pytest.fixture
def ssl_paths(tmp_path: Path) -> tuple[Path, Path]:
    """Return the paths the HTTP server is configured with."""
    return tmp_path / "ssl" / "fullchain.pem", tmp_path / "ssl" / "privkey.pem"


@pytest.fixture
def mock_http(hass: HomeAssistant, ssl_paths: tuple[Path, Path]) -> SimpleNamespace:
    """Stand in for an HTTP server that serves TLS."""
    http = SimpleNamespace(
        ssl_certificate=str(ssl_paths[0]),
        ssl_key=str(ssl_paths[1]),
        context=MagicMock(),
    )
    hass.http = http
    hass.config.components.add("http")
    return http


@pytest.fixture
def entry_options() -> dict[str, object]:
    """Return config entry options; override to enable Dynamic DNS."""
    return {CONF_UPDATE_INTERVAL: DEFAULT_UPDATE_INTERVAL, CONF_DYNAMIC_DNS: False}


@pytest.fixture
def mock_config_entry(entry_options: dict[str, object]) -> MockConfigEntry:
    """Return a config entry."""
    return MockConfigEntry(
        domain=DOMAIN, title=FQDN, data=ENTRY_DATA, options=entry_options
    )
