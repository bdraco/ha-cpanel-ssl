"""Config flow for cPanel SSL."""

from collections.abc import Mapping
import logging
from typing import Any
from urllib.parse import urlparse

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import (
    CONF_API_TOKEN,
    CONF_HOST,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import (
    CpanelApiError,
    CpanelAuthError,
    CpanelClient,
    CpanelConnectionError,
    CpanelNoCertificateError,
)
from .const import (
    CONF_DOMAIN,
    CONF_UPDATE_INTERVAL,
    CONF_WEBCALL_URL,
    DEFAULT_PORT,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
)
from .coordinator import CpanelSslConfigEntry

_LOGGER = logging.getLogger(__name__)

PASSWORD_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
URL_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.URL))


async def _async_validate(
    flow: ConfigFlow, data: Mapping[str, Any]
) -> tuple[dict[str, str], dict[str, str]]:
    """Fetch the certificate once; return errors and description placeholders."""
    client = CpanelClient(
        async_get_clientsession(flow.hass),
        data[CONF_HOST],
        data[CONF_PORT],
        data[CONF_USERNAME],
        data[CONF_API_TOKEN],
        data[CONF_VERIFY_SSL],
    )
    try:
        await client.fetch_certificate(data[CONF_DOMAIN])
    except CpanelAuthError:
        return {"base": "invalid_auth"}, {}
    except CpanelConnectionError:
        return {"base": "cannot_connect"}, {}
    except CpanelNoCertificateError:
        return {"base": "no_certificate"}, {}
    except CpanelApiError as err:
        return {"base": "api_error"}, {"error": str(err)}
    except Exception:
        _LOGGER.exception("Unexpected error validating cPanel credentials")
        return {"base": "unknown"}, {}
    return {}, {}


def _build_options(user_input: Mapping[str, Any]) -> dict[str, Any]:
    """Return entry options, dropping an empty webcall URL."""
    options: dict[str, Any] = {
        CONF_UPDATE_INTERVAL: int(
            user_input.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL)
        )
    }
    if webcall_url := user_input.get(CONF_WEBCALL_URL):
        options[CONF_WEBCALL_URL] = webcall_url
    return options


class CpanelSslConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for cPanel SSL."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the cPanel account and domain."""
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {}
        if user_input is not None:
            user_input[CONF_DOMAIN] = user_input[CONF_DOMAIN].strip().lower()
            await self.async_set_unique_id(user_input[CONF_DOMAIN])
            self._abort_if_unique_id_configured()
            errors, placeholders = await _async_validate(self, user_input)
            if not errors:
                return self.async_create_entry(
                    title=user_input[CONF_DOMAIN],
                    data={
                        key: user_input[key]
                        for key in (
                            CONF_HOST,
                            CONF_PORT,
                            CONF_USERNAME,
                            CONF_API_TOKEN,
                            CONF_VERIFY_SSL,
                            CONF_DOMAIN,
                        )
                    },
                    options=_build_options(user_input),
                )

        suggested = user_input or {}
        if CONF_DOMAIN not in suggested and self.hass.config.external_url:
            suggested = {CONF_DOMAIN: urlparse(self.hass.config.external_url).hostname}
        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_PORT, default=DEFAULT_PORT): vol.Coerce(int),
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_API_TOKEN): PASSWORD_SELECTOR,
                vol.Required(CONF_DOMAIN): str,
                vol.Required(CONF_VERIFY_SSL, default=True): bool,
                vol.Optional(CONF_WEBCALL_URL): URL_SELECTOR,
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(schema, suggested),
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle a rejected API token."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for a new API token."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {}
        if user_input is not None:
            data = {**entry.data, CONF_API_TOKEN: user_input[CONF_API_TOKEN]}
            errors, placeholders = await _async_validate(self, data)
            if not errors:
                return self.async_update_reload_and_abort(entry, data=data)
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_API_TOKEN): PASSWORD_SELECTOR}),
            errors=errors,
            description_placeholders={
                CONF_USERNAME: entry.data[CONF_USERNAME],
                CONF_HOST: entry.data[CONF_HOST],
                **placeholders,
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: CpanelSslConfigEntry) -> OptionsFlow:
        """Return the options flow."""
        return CpanelSslOptionsFlow()


class CpanelSslOptionsFlow(OptionsFlow):
    """Change the update interval and Dynamic DNS webcall."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(data=_build_options(user_input))
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_UPDATE_INTERVAL, default=DEFAULT_UPDATE_INTERVAL
                ): NumberSelector(
                    NumberSelectorConfig(
                        min=1,
                        max=168,
                        step=1,
                        unit_of_measurement="h",
                        mode=NumberSelectorMode.BOX,
                    )
                ),
                vol.Optional(CONF_WEBCALL_URL): URL_SELECTOR,
            }
        )
        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                schema, self.config_entry.options
            ),
        )
