"""Tests for installing the certificate."""

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from freezegun.api import FrozenDateTimeFactory
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
    async_mock_service,
)
from pytest_homeassistant_custom_component.test_util.aiohttp import (
    AiohttpClientMocker,
)

from custom_components.cpanel_ssl.const import DOMAIN
from homeassistant.components.button import DOMAIN as BUTTON_DOMAIN, SERVICE_PRESS
from homeassistant.components.http.config import async_get_and_load_store
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID, STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.util import dt as dt_util

from .conftest import (
    AUTOSSL_URL,
    DDNS_ID,
    DDNS_LIST_URL,
    DDNS_OPTIONS,
    FETCH_URL,
    FQDN,
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


def _http_storage(pending: dict[str, Any] | None) -> dict[str, Any]:
    """Return stored HTTP config with an optional pending trial."""
    return {
        "version": 2,
        "minor_version": 2,
        "key": "http",
        "data": {
            "stable": {"server_port": 8123, "created_at": None, "error": None},
            "pending": pending,
            "yaml_migration_done": True,
        },
    }


@pytest.fixture
def https_off(mock_http: SimpleNamespace, hass: HomeAssistant, tmp_path: Path) -> Path:
    """Run as if HTTPS is not configured; return the ssl directory used."""
    mock_http.ssl_certificate = None
    mock_http.ssl_key = None
    hass.config.config_dir = str(tmp_path / "config")
    return tmp_path / "config" / "ssl"


@pytest.mark.usefixtures("mock_cpanel")
async def test_enables_https(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_http: SimpleNamespace,
    https_off: Path,
) -> None:
    """Test the certificate is staged as a pending HTTP config and HA restarts."""
    restart_calls = async_mock_service(hass, "homeassistant", "restart")
    await _setup(hass, mock_config_entry)

    assert (https_off / "fullchain.pem").exists()
    mock_http.context.load_cert_chain.assert_not_called()
    assert len(restart_calls) == 1
    pending = (await async_get_and_load_store(hass)).pending
    assert pending["server_port"] == 8123
    assert pending["ssl_certificate"] == str(https_off / "fullchain.pem")
    assert pending["ssl_key"] == str(https_off / "privkey.pem")


@pytest.mark.usefixtures("mock_cpanel")
async def test_reverted_https_trial_not_retried(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    issue_registry: ir.IssueRegistry,
    mock_config_entry: MockConfigEntry,
    https_off: Path,
) -> None:
    """Test a reverted trial is not staged again, which would restart in a loop."""
    hass_storage["http"] = _http_storage(
        {"ssl_certificate": str(https_off / "fullchain.pem"), "error": "not_promoted"}
    )
    restart_calls = async_mock_service(hass, "homeassistant", "restart")
    await _setup(hass, mock_config_entry)

    assert restart_calls == []
    assert issue_registry.async_get_issue(DOMAIN, "https_not_confirmed")


@pytest.mark.usefixtures("mock_cpanel")
async def test_user_http_trial_left_alone(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    issue_registry: ir.IssueRegistry,
    mock_config_entry: MockConfigEntry,
    https_off: Path,
) -> None:
    """Test a trial the user staged is not replaced."""
    hass_storage["http"] = _http_storage(
        {"ssl_certificate": "/other/cert.pem", "error": None}
    )
    restart_calls = async_mock_service(hass, "homeassistant", "restart")
    await _setup(hass, mock_config_entry)

    assert restart_calls == []
    assert issue_registry.async_get_issue(DOMAIN, "https_not_confirmed") is None


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
@pytest.mark.parametrize("entry_options", [DDNS_OPTIONS])
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
@pytest.mark.parametrize("entry_options", [DDNS_OPTIONS])
async def test_webcall_runs_while_certificate_fails(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the IP is still updated when the certificate cannot be fetched."""
    aioclient_mock.get(FETCH_URL, status=500)
    aioclient_mock.get(DDNS_LIST_URL, json=uapi_ok([{"domain": FQDN, "id": DDNS_ID}]))
    aioclient_mock.get(WEBCALL_URL, text="OK")
    await _setup(hass, mock_config_entry)
    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY
    assert _calls(aioclient_mock, WEBCALL_URL) == 1


@pytest.mark.usefixtures("mock_http", "mock_cpanel")
@pytest.mark.parametrize("entry_options", [DDNS_OPTIONS])
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


@pytest.mark.usefixtures("mock_http")
async def test_waits_for_autossl(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
    ssl_paths: tuple[Path, Path],
    certificate: dict[str, str],
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test AutoSSL is asked once and the certificate installed when issued."""
    aioclient_mock.get(FETCH_URL, json=uapi_ok(None))
    aioclient_mock.get(AUTOSSL_URL, json=uapi_ok(None))
    await _setup(hass, mock_config_entry)
    assert mock_config_entry.state is ConfigEntryState.LOADED
    assert hass.states.get(EXPIRY_ENTITY).state == STATE_UNKNOWN
    assert _calls(aioclient_mock, AUTOSSL_URL) == 1

    freezer.tick(timedelta(minutes=15))
    async_fire_time_changed(hass)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert _calls(aioclient_mock, FETCH_URL) == 2
    assert _calls(aioclient_mock, AUTOSSL_URL) == 1

    aioclient_mock.clear_requests()
    aioclient_mock.get(FETCH_URL, json=uapi_ok(certificate))
    freezer.tick(timedelta(minutes=15))
    async_fire_time_changed(hass)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert ssl_paths[0].read_text() == pem(certificate["crt"])
    assert hass.states.get(EXPIRY_ENTITY).state == "2027-01-01T00:00:00+00:00"


@pytest.mark.parametrize("entry_options", [DDNS_OPTIONS])
@pytest.mark.usefixtures("mock_http")
async def test_dynamic_dns_lookup_fails(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test setup is retried when the Dynamic DNS record cannot be found."""
    aioclient_mock.get(DDNS_LIST_URL, status=500)
    await _setup(hass, mock_config_entry)
    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY
