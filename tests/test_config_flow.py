"""Tests for the cPanel SSL config flow."""

from typing import Any

import aiohttp
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
from homeassistant.config_entries import SOURCE_USER
from homeassistant.const import CONF_API_TOKEN
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from .conftest import (
    ENTRY_DATA,
    FETCH_URL,
    FQDN,
    WEBCALL_OPTIONS,
    WEBCALL_URL,
    uapi_ok,
)

USER_INPUT = {**ENTRY_DATA, CONF_DOMAIN: " Home.Example.com "}


@pytest.fixture(autouse=True)
def _mock_setup(mock_cpanel: AiohttpClientMocker, mock_http: object) -> None:
    """Let created entries set up against the mocked cPanel."""


async def test_user_flow(hass: HomeAssistant) -> None:
    """Test creating an entry with a webcall."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**USER_INPUT, CONF_WEBCALL_URL: WEBCALL_URL}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == FQDN
    assert result["data"] == ENTRY_DATA
    assert result["options"] == {
        CONF_UPDATE_INTERVAL: 12,
        CONF_WEBCALL_URL: WEBCALL_URL,
    }


async def test_user_flow_suggests_external_url(hass: HomeAssistant) -> None:
    """Test the domain is prefilled from the external URL."""
    hass.config.external_url = f"https://{FQDN}:8123"
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    schema_keys = {str(key): key for key in result["data_schema"].schema}
    assert schema_keys[CONF_DOMAIN].description == {"suggested_value": FQDN}


@pytest.mark.parametrize(
    ("response", "error"),
    [
        pytest.param({"status": 401}, "invalid_auth", id="invalid_auth"),
        pytest.param(
            {"exc": aiohttp.ClientConnectionError()},
            "cannot_connect",
            id="cannot_connect",
        ),
        pytest.param({"json": uapi_ok(None)}, "no_certificate", id="no_certificate"),
        pytest.param(
            {"json": {"result": {"status": 0, "errors": ["Feature disabled"]}}},
            "api_error",
            id="api_error",
        ),
    ],
)
async def test_user_flow_errors(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    certificate: dict[str, str],
    response: dict[str, Any],
    error: str,
) -> None:
    """Test errors are shown and the flow recovers."""
    aioclient_mock.clear_requests()
    aioclient_mock.get(FETCH_URL, **response)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    aioclient_mock.clear_requests()
    aioclient_mock.get(FETCH_URL, json=uapi_ok(certificate))
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


@pytest.mark.parametrize("entry_options", [WEBCALL_OPTIONS])
async def test_options_flow(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test clearing the webcall and changing the interval."""
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_UPDATE_INTERVAL: 6.0}
    )
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_config_entry.options == {CONF_UPDATE_INTERVAL: 6}
