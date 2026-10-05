"""Tests for the cPanel SSL config flow."""

from typing import Any
from unittest.mock import AsyncMock

from aiocpanel import (
    CpanelApiError,
    CpanelAuthError,
    CpanelConnectionError,
    CpanelNoCertificateError,
)
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cpanel_ssl.const import (
    CONF_DOMAIN,
    CONF_DYNAMIC_DNS,
    CONF_UPDATE_INTERVAL,
    DOMAIN,
)
from homeassistant.config_entries import SOURCE_USER
from homeassistant.const import CONF_API_TOKEN
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from .conftest import DDNS_OPTIONS, ENTRY_DATA, FQDN

USER_INPUT = {**ENTRY_DATA, CONF_DOMAIN: " Home.Example.com ", CONF_DYNAMIC_DNS: True}

pytestmark = pytest.mark.usefixtures("mock_http")


async def _async_submit(hass: HomeAssistant, user_input: dict[str, Any]) -> Any:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    return await hass.config_entries.flow.async_configure(result["flow_id"], user_input)


async def test_user_flow(hass: HomeAssistant, mock_cpanel_client: AsyncMock) -> None:
    """Test creating an entry that manages Dynamic DNS."""
    result = await _async_submit(hass, USER_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == FQDN
    assert result["data"] == ENTRY_DATA
    assert result["options"] == DDNS_OPTIONS
    mock_cpanel_client.ensure_dynamic_dns.assert_any_call(FQDN, "Home Assistant")


async def test_user_flow_without_certificate(
    hass: HomeAssistant, mock_cpanel_client: AsyncMock
) -> None:
    """Test setup continues when AutoSSL has not issued a certificate yet."""
    mock_cpanel_client.fetch_certificate.side_effect = CpanelNoCertificateError
    result = await _async_submit(hass, {**USER_INPUT, CONF_DYNAMIC_DNS: False})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["options"] == {CONF_UPDATE_INTERVAL: 12, CONF_DYNAMIC_DNS: False}
    mock_cpanel_client.ensure_dynamic_dns.assert_not_called()


@pytest.mark.usefixtures("mock_cpanel_client")
async def test_user_flow_suggests_external_url(hass: HomeAssistant) -> None:
    """Test the domain is prefilled from the external URL."""
    hass.config.external_url = f"https://{FQDN}:8123"
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    schema_keys = {str(key): key for key in result["data_schema"].schema}
    assert schema_keys[CONF_DOMAIN].description == {"suggested_value": FQDN}


@pytest.mark.parametrize(
    ("method", "exception", "error"),
    [
        pytest.param(
            "fetch_certificate", CpanelAuthError, "invalid_auth", id="invalid_auth"
        ),
        pytest.param(
            "fetch_certificate",
            CpanelConnectionError,
            "cannot_connect",
            id="cannot_connect",
        ),
        pytest.param(
            "fetch_certificate", CpanelApiError("nope"), "api_error", id="api_error"
        ),
        pytest.param(
            "ensure_dynamic_dns",
            CpanelApiError("no DDNS"),
            "api_error",
            id="dynamic_dns_error",
        ),
        pytest.param("fetch_certificate", RuntimeError, "unknown", id="unknown"),
    ],
)
async def test_user_flow_errors(
    hass: HomeAssistant,
    mock_cpanel_client: AsyncMock,
    method: str,
    exception: Exception | type[Exception],
    error: str,
) -> None:
    """Test errors are shown and the flow recovers."""
    getattr(mock_cpanel_client, method).side_effect = exception
    result = await _async_submit(hass, USER_INPUT)
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    getattr(mock_cpanel_client, method).side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_single_instance(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test only one entry is allowed."""
    mock_config_entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "single_instance_allowed"


@pytest.mark.usefixtures("mock_cpanel_client")
async def test_reauth(hass: HomeAssistant, mock_config_entry: MockConfigEntry) -> None:
    """Test replacing the API token."""
    mock_config_entry.add_to_hass(hass)
    result = await mock_config_entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_API_TOKEN: "new"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert mock_config_entry.data[CONF_API_TOKEN] == "new"


@pytest.mark.parametrize("entry_options", [DDNS_OPTIONS])
@pytest.mark.usefixtures("mock_cpanel_client")
async def test_options_flow(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test turning off Dynamic DNS and changing the interval."""
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_UPDATE_INTERVAL: 6.0, CONF_DYNAMIC_DNS: False}
    )
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_config_entry.options == {
        CONF_UPDATE_INTERVAL: 6,
        CONF_DYNAMIC_DNS: False,
    }
