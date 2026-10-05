"""The cPanel SSL integration."""

from datetime import datetime, timedelta

from homeassistant.const import (
    CONF_API_TOKEN,
    CONF_HOST,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    Platform,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_track_time_interval

from .api import CpanelClient
from .const import DOMAIN
from .coordinator import CpanelSslConfigEntry, CpanelSslCoordinator

PLATFORMS = [Platform.BUTTON, Platform.SENSOR]

DYNAMIC_DNS_INTERVAL = timedelta(minutes=5)


async def async_setup_entry(hass: HomeAssistant, entry: CpanelSslConfigEntry) -> bool:
    """Set up cPanel SSL from a config entry."""
    client = CpanelClient(
        async_get_clientsession(hass),
        entry.data[CONF_HOST],
        entry.data[CONF_PORT],
        entry.data[CONF_USERNAME],
        entry.data[CONF_API_TOKEN],
        entry.data[CONF_VERIFY_SSL],
    )
    coordinator = CpanelSslCoordinator(hass, entry, client)

    # A restart picks up whatever is on disk, so a pending restart issue is stale.
    ir.async_delete_issue(hass, DOMAIN, "restart_required")
    if coordinator.http_ssl_configured:
        ir.async_delete_issue(hass, DOMAIN, "ssl_not_configured")
    else:
        ir.async_create_issue(
            hass,
            DOMAIN,
            "ssl_not_configured",
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="ssl_not_configured",
            translation_placeholders={
                "cert_path": str(coordinator.cert_path),
                "key_path": str(coordinator.key_path),
            },
        )

    # Keep the IP current even while the certificate cannot be fetched.
    if coordinator.webcall_url:

        async def _async_update_dynamic_dns(_now: datetime) -> None:
            await coordinator.async_update_dynamic_dns()

        entry.async_on_unload(
            async_track_time_interval(
                hass, _async_update_dynamic_dns, DYNAMIC_DNS_INTERVAL
            )
        )
        entry.async_create_background_task(
            hass, coordinator.async_update_dynamic_dns(), "cpanel_ssl_dynamic_dns"
        )

    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_update_listener(
    hass: HomeAssistant, entry: CpanelSslConfigEntry
) -> None:
    """Reload when options change."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: CpanelSslConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
