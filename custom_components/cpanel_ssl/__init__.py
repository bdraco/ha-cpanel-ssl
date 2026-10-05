"""The cPanel SSL integration."""

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .api import async_create_client
from .const import CONF_WEBCALL_URL
from .coordinator import (
    CpanelSslConfigEntry,
    CpanelSslCoordinator,
    CpanelSslRuntimeData,
)
from .dynamic_dns import DynamicDnsUpdater

PLATFORMS = [Platform.BUTTON, Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: CpanelSslConfigEntry) -> bool:
    """Set up cPanel SSL from a config entry."""
    client = async_create_client(hass, entry.data)

    dynamic_dns: DynamicDnsUpdater | None = None
    if webcall_url := entry.options.get(CONF_WEBCALL_URL):
        dynamic_dns = DynamicDnsUpdater(hass, client, webcall_url)
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
