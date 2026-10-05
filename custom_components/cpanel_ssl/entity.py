"""Base entity for cPanel SSL."""

from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CpanelSslCoordinator


class CpanelSslEntity(CoordinatorEntity[CpanelSslCoordinator]):
    """An entity tied to the certificate for one domain."""

    _attr_has_entity_name = True

    def __init__(
        self, coordinator: CpanelSslCoordinator, description: EntityDescription
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self.entity_description = description
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=coordinator.domain,
            manufacturer="cPanel",
            entry_type=DeviceEntryType.SERVICE,
            configuration_url=f"https://{entry.data[CONF_HOST]}:{entry.data[CONF_PORT]}",
        )
