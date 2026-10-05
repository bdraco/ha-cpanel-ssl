"""The cPanel SSL integration."""

from aiocpanel import CpanelAuthError, CpanelError

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

from .const import CONF_DOMAIN, CONF_DYNAMIC_DNS, DYNAMIC_DNS_DESCRIPTION
from .coordinator import (
    CpanelSslConfigEntry,
    CpanelSslCoordinator,
    CpanelSslRuntimeData,
    async_create_client,
)
from .dynamic_dns import DynamicDnsUpdater

PLATFORMS = [Platform.BUTTON, Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: CpanelSslConfigEntry) -> bool:
    """Set up cPanel SSL from a config entry."""
    client = async_create_client(hass, entry.data)

    dynamic_dns: DynamicDnsUpdater | None = None
    if entry.options.get(CONF_DYNAMIC_DNS):
        try:
            record = await client.ensure_dynamic_dns(
                entry.data[CONF_DOMAIN], DYNAMIC_DNS_DESCRIPTION
            )
        except CpanelAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except CpanelError as err:
            raise ConfigEntryNotReady(f"Error setting up Dynamic DNS: {err}") from err
        dynamic_dns = DynamicDnsUpdater(hass, client, record)
        # Started first so the IP is updated even if the certificate fetch fails.
        dynamic_dns.async_start(entry)

    coordinator = CpanelSslCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = CpanelSslRuntimeData(coordinator, dynamic_dns)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: CpanelSslConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
