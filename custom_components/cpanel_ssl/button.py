"""Buttons for cPanel SSL."""

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .api import CpanelError
from .coordinator import CpanelSslConfigEntry, CpanelSslCoordinator
from .dynamic_dns import DynamicDnsUpdater
from .entity import CpanelSslEntity

PARALLEL_UPDATES = 1

REFRESH_DESCRIPTION = ButtonEntityDescription(
    key="refresh_certificate",
    translation_key="refresh_certificate",
    entity_category=EntityCategory.CONFIG,
)
UPDATE_IP_DESCRIPTION = ButtonEntityDescription(
    key="update_ip",
    translation_key="update_ip",
    entity_category=EntityCategory.CONFIG,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CpanelSslConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the buttons."""
    data = entry.runtime_data
    entities: list[ButtonEntity] = [CpanelSslRefreshButton(entry, data.coordinator)]
    if data.dynamic_dns:
        entities.append(CpanelSslUpdateIpButton(entry, data.dynamic_dns))
    async_add_entities(entities)


class CpanelSslRefreshButton(CpanelSslEntity, ButtonEntity):
    """Fetch the certificate from cPanel now."""

    def __init__(
        self, entry: CpanelSslConfigEntry, coordinator: CpanelSslCoordinator
    ) -> None:
        """Initialize the button."""
        super().__init__(entry, REFRESH_DESCRIPTION)
        self._coordinator = coordinator

    async def async_press(self) -> None:
        """Refresh the certificate."""
        await self._coordinator.async_request_refresh()


class CpanelSslUpdateIpButton(CpanelSslEntity, ButtonEntity):
    """Call the Dynamic DNS webcall now."""

    def __init__(
        self, entry: CpanelSslConfigEntry, dynamic_dns: DynamicDnsUpdater
    ) -> None:
        """Initialize the button."""
        super().__init__(entry, UPDATE_IP_DESCRIPTION)
        self._dynamic_dns = dynamic_dns

    async def async_press(self) -> None:
        """Update the Dynamic DNS record."""
        try:
            await self._dynamic_dns.async_update()
        except CpanelError as err:
            raise HomeAssistantError(f"Dynamic DNS update failed: {err}") from err
