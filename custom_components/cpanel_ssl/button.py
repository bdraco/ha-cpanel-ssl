"""Buttons for cPanel SSL."""

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import CpanelSslConfigEntry
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
    coordinator = entry.runtime_data
    entities: list[ButtonEntity] = [
        CpanelSslRefreshButton(coordinator, REFRESH_DESCRIPTION)
    ]
    if coordinator.webcall_url:
        entities.append(CpanelSslUpdateIpButton(coordinator, UPDATE_IP_DESCRIPTION))
    async_add_entities(entities)


class CpanelSslRefreshButton(CpanelSslEntity, ButtonEntity):
    """Fetch the certificate from cPanel now."""

    async def async_press(self) -> None:
        """Refresh the certificate."""
        await self.coordinator.async_request_refresh()


class CpanelSslUpdateIpButton(CpanelSslEntity, ButtonEntity):
    """Call the Dynamic DNS webcall now."""

    @property
    def available(self) -> bool:
        """Stay usable even when the certificate fetch is failing."""
        return True

    async def async_press(self) -> None:
        """Update the Dynamic DNS record."""
        await self.coordinator.async_update_dynamic_dns(raise_on_error=True)
