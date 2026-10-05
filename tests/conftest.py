"""Fixtures for cPanel SSL tests."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.test_util.aiohttp import (
    AiohttpClientMocker,
)

from custom_components.cpanel_ssl.const import (
    CONF_DOMAIN,
    CONF_UPDATE_INTERVAL,
    CONF_WEBCALL_URL,
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
FETCH_URL = f"https://{HOST}:2083/execute/SSL/fetch_best_for_domain?domain={FQDN}"
AUTOSSL_URL = f"https://{HOST}:2083/execute/SSL/start_autossl_check"
WEBCALL_URL = f"https://{HOST}:2083/cpanelwebcall/abcdefghijklmnopqrstuvwxyzabcdef"
NOT_AFTER = datetime(2027, 1, 1, tzinfo=UTC)

ENTRY_DATA = {
    CONF_HOST: HOST,
    CONF_PORT: 2083,
    CONF_USERNAME: "user",
    CONF_API_TOKEN: "token",
    CONF_VERIFY_SSL: True,
    CONF_DOMAIN: FQDN,
}


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Enable custom integrations in every test."""


def make_certificate(not_after: datetime = NOT_AFTER) -> dict[str, str]:
    """Return a self signed cert and key as cPanel would."""
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
    return {
        "crt": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "key": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        "cab": None,
    }


def uapi_ok(data: object) -> dict[str, object]:
    """Wrap data in a successful UAPI response."""
    return {"result": {"status": 1, "data": data, "errors": None}}


@pytest.fixture
def certificate() -> dict[str, str]:
    """Return a certificate served by the mocked cPanel."""
    return make_certificate()


@pytest.fixture
def mock_cpanel(
    aioclient_mock: AiohttpClientMocker, certificate: dict[str, str]
) -> AiohttpClientMocker:
    """Mock a cPanel account with a certificate."""
    aioclient_mock.get(FETCH_URL, json=uapi_ok(certificate))
    aioclient_mock.get(AUTOSSL_URL, json=uapi_ok(None))
    aioclient_mock.get(WEBCALL_URL, text="OK")
    return aioclient_mock


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
def mock_config_entry() -> MockConfigEntry:
    """Return a config entry."""
    return MockConfigEntry(
        domain=DOMAIN,
        title=FQDN,
        unique_id=FQDN,
        data=ENTRY_DATA,
        options={CONF_UPDATE_INTERVAL: 12},
    )


@pytest.fixture
def mock_config_entry_webcall() -> MockConfigEntry:
    """Return a config entry with a Dynamic DNS webcall."""
    return MockConfigEntry(
        domain=DOMAIN,
        title=FQDN,
        unique_id=FQDN,
        data=ENTRY_DATA,
        options={CONF_UPDATE_INTERVAL: 12, CONF_WEBCALL_URL: WEBCALL_URL},
    )
