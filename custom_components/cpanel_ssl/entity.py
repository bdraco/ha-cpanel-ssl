"""Base entity for cPanel SSL."""

from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity import Entity, EntityDescription

from .const import CONF_DOMAIN, DOMAIN
from .coordinator import CpanelSslConfigEntry


class CpanelSslEntity(Entity):
    """An entity tied to the certificate for one domain."""

    _attr_has_entity_name = True

    def __init__(
        self, entry: CpanelSslConfigEntry, description: EntityDescription
    ) -> None:
        """Initialize the entity."""
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.data[CONF_DOMAIN],
            manufacturer="cPanel",
            entry_type=DeviceEntryType.SERVICE,
            configuration_url=f"https://{entry.data[CONF_HOST]}:{entry.data[CONF_PORT]}",
        )
