"""Tests for installing the certificate."""

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from freezegun.api import FrozenDateTimeFactory
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)
from pytest_homeassistant_custom_component.test_util.aiohttp import (
    AiohttpClientMocker,
)

from custom_components.cpanel_ssl.const import DOMAIN
from homeassistant.components.button import DOMAIN as BUTTON_DOMAIN, SERVICE_PRESS
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.util import dt as dt_util

from .conftest import (
    AUTOSSL_URL,
    FETCH_URL,
    WEBCALL_OPTIONS,
    WEBCALL_URL,
    make_certificate,
    pem,
    uapi_ok,
)

EXPIRY_ENTITY = "sensor.home_example_com_certificate_expiry"
REFRESH_ENTITY = "button.home_example_com_refresh_certificate"
UPDATE_IP_ENTITY = "button.home_example_com_update_ip"


def _calls(aioclient_mock: AiohttpClientMocker, url: str) -> int:
    """Count requests to a URL."""
    return sum(1 for call in aioclient_mock.mock_calls if str(call[1]) == url)


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


@pytest.mark.usefixtures("mock_cpanel")
async def test_installs_and_reloads(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_http: SimpleNamespace,
    ssl_paths: tuple[Path, Path],
    certificate: dict[str, str],
) -> None:
    """Test the certificate is written and loaded into the server."""
    await _setup(hass, mock_config_entry)
    assert mock_config_entry.state is ConfigEntryState.LOADED

    cert_path, key_path = ssl_paths
    assert cert_path.read_text() == pem(certificate["crt"])
    assert key_path.read_text() == pem(certificate["key"])
    assert key_path.stat().st_mode & 0o777 == 0o600
    mock_http.context.load_cert_chain.assert_called_once_with(cert_path, key_path)

    state = hass.states.get(EXPIRY_ENTITY)
    assert state.state == "2027-01-01T00:00:00+00:00"
    assert hass.states.get(UPDATE_IP_ENTITY) is None


@pytest.mark.usefixtures("mock_cpanel")
async def test_unchanged_certificate_not_reloaded(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_http: SimpleNamespace,
    ssl_paths: tuple[Path, Path],
    certificate: dict[str, str],
) -> None:
    """Test nothing is rewritten when the files already match."""
    cert_path, key_path = ssl_paths
    cert_path.parent.mkdir()
    cert_path.write_text(pem(certificate["crt"]))
    key_path.write_text(pem(certificate["key"]))
    mtime = cert_path.stat().st_mtime_ns

    await _setup(hass, mock_config_entry)
    assert cert_path.stat().st_mtime_ns == mtime
    mock_http.context.load_cert_chain.assert_not_called()


@pytest.mark.usefixtures("mock_http")
async def test_mismatched_key_not_installed(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
    ssl_paths: tuple[Path, Path],
) -> None:
    """Test a cert and key that do not match are never written."""
    aioclient_mock.get(
        FETCH_URL,
        json=uapi_ok({**make_certificate(), "key": make_certificate()["key"]}),
    )
    await _setup(hass, mock_config_entry)
    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY
    assert not ssl_paths[0].exists()
    assert not ssl_paths[1].exists()


@pytest.mark.usefixtures("mock_cpanel")
async def test_new_certificate_installed_on_refresh(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
    mock_http: SimpleNamespace,
    ssl_paths: tuple[Path, Path],
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test a renewed certificate replaces the old one."""
    await _setup(hass, mock_config_entry)
    renewed = make_certificate(dt_util.parse_datetime("2027-04-01T00:00:00+00:00"))
    aioclient_mock.clear_requests()
    aioclient_mock.get(FETCH_URL, json=uapi_ok(renewed))

    freezer.tick(timedelta(hours=12))
    async_fire_time_changed(hass)
    await hass.async_block_till_done(wait_background_tasks=True)

    assert ssl_paths[0].read_text() == pem(renewed["crt"])
    assert mock_http.context.load_cert_chain.call_count == 2
    assert hass.states.get(EXPIRY_ENTITY).state == "2027-04-01T00:00:00+00:00"


@pytest.mark.usefixtures("mock_http")
async def test_expiring_certificate_starts_autossl(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test AutoSSL is nudged when the certificate is about to expire."""
    aioclient_mock.get(
        FETCH_URL,
        json=uapi_ok(make_certificate(dt_util.utcnow() + timedelta(days=3))),
    )
    aioclient_mock.get(AUTOSSL_URL, json=uapi_ok(None))
    await _setup(hass, mock_config_entry)
    assert _calls(aioclient_mock, AUTOSSL_URL) == 1


@pytest.mark.usefixtures("mock_cpanel")
async def test_recovery_mode_without_context(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_http: SimpleNamespace,
    ssl_paths: tuple[Path, Path],
) -> None:
    """Test the certificate is still written when the server has no context."""
    mock_http.context = None
    await _setup(hass, mock_config_entry)
    assert mock_config_entry.state is ConfigEntryState.LOADED
    assert ssl_paths[0].exists()


@pytest.mark.usefixtures("mock_cpanel")
async def test_ssl_not_configured(
    hass: HomeAssistant,
    issue_registry: ir.IssueRegistry,
    mock_config_entry: MockConfigEntry,
    mock_http: SimpleNamespace,
    tmp_path: Path,
) -> None:
    """Test the cert is saved and the user is told how to enable HTTPS."""
    mock_http.ssl_certificate = None
    mock_http.ssl_key = None
    hass.config.config_dir = str(tmp_path / "config")
    await _setup(hass, mock_config_entry)

    assert (tmp_path / "config" / "ssl" / "fullchain.pem").exists()
    assert issue_registry.async_get_issue(DOMAIN, "ssl_not_configured")
    mock_http.context.load_cert_chain.assert_not_called()


@pytest.mark.usefixtures("mock_http")
async def test_auth_failure_starts_reauth(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test a rejected token starts reauth."""
    aioclient_mock.get(FETCH_URL, status=401)
    await _setup(hass, mock_config_entry)
    assert mock_config_entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert [flow["context"]["source"] for flow in flows] == [SOURCE_REAUTH]


@pytest.mark.usefixtures("mock_http", "mock_cpanel")
async def test_refresh_button(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the refresh button fetches the certificate again."""
    await _setup(hass, mock_config_entry)
    await hass.services.async_call(
        BUTTON_DOMAIN, SERVICE_PRESS, {ATTR_ENTITY_ID: REFRESH_ENTITY}, blocking=True
    )
    assert _calls(aioclient_mock, FETCH_URL) == 2


@pytest.mark.usefixtures("mock_http", "mock_cpanel")
@pytest.mark.parametrize("entry_options", [WEBCALL_OPTIONS])
async def test_webcall(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test the webcall runs at setup, on a timer and from the button."""
    await _setup(hass, mock_config_entry)
    assert _calls(aioclient_mock, WEBCALL_URL) == 1

    freezer.tick(timedelta(minutes=5))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    assert _calls(aioclient_mock, WEBCALL_URL) == 2

    await hass.services.async_call(
        BUTTON_DOMAIN, SERVICE_PRESS, {ATTR_ENTITY_ID: UPDATE_IP_ENTITY}, blocking=True
    )
    assert _calls(aioclient_mock, WEBCALL_URL) == 3


@pytest.mark.usefixtures("mock_http")
@pytest.mark.parametrize("entry_options", [WEBCALL_OPTIONS])
async def test_webcall_runs_while_certificate_fails(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the IP is still updated when the certificate cannot be fetched."""
    aioclient_mock.get(FETCH_URL, status=500)
    aioclient_mock.get(WEBCALL_URL, text="OK")
    await _setup(hass, mock_config_entry)
    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY
    assert _calls(aioclient_mock, WEBCALL_URL) == 1


@pytest.mark.usefixtures("mock_http", "mock_cpanel")
@pytest.mark.parametrize("entry_options", [WEBCALL_OPTIONS])
async def test_update_ip_button_error(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
    certificate: dict[str, str],
) -> None:
    """Test the update IP button raises when the webcall fails."""
    await _setup(hass, mock_config_entry)
    aioclient_mock.clear_requests()
    aioclient_mock.get(WEBCALL_URL, status=500)
    aioclient_mock.get(FETCH_URL, json=uapi_ok(certificate))

    with pytest.raises(HomeAssistantError, match="Dynamic DNS update failed"):
        await hass.services.async_call(
            BUTTON_DOMAIN,
            SERVICE_PRESS,
            {ATTR_ENTITY_ID: UPDATE_IP_ENTITY},
            blocking=True,
        )


@pytest.mark.usefixtures("mock_http", "mock_cpanel")
async def test_unload(hass: HomeAssistant, mock_config_entry: MockConfigEntry) -> None:
    """Test unloading the entry."""
    await _setup(hass, mock_config_entry)
    assert await hass.config_entries.async_unload(mock_config_entry.entry_id)
    assert mock_config_entry.state is ConfigEntryState.NOT_LOADED
