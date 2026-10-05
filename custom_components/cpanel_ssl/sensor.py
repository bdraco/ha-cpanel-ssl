"""Certificate expiry sensor for cPanel SSL."""

from datetime import datetime

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .coordinator import CpanelSslConfigEntry, CpanelSslCoordinator
from .entity import device_info

PARALLEL_UPDATES = 0

EXPIRY_DESCRIPTION = SensorEntityDescription(
    key="certificate_expiry",
    translation_key="certificate_expiry",
    device_class=SensorDeviceClass.TIMESTAMP,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CpanelSslConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the certificate expiry sensor."""
    async_add_entities([CpanelSslExpirySensor(entry, EXPIRY_DESCRIPTION)])


class CpanelSslExpirySensor(CoordinatorEntity[CpanelSslCoordinator], SensorEntity):
    """When the installed certificate expires."""

    _attr_has_entity_name = True

    def __init__(
        self, entry: CpanelSslConfigEntry, description: SensorEntityDescription
    ) -> None:
        """Initialize the sensor."""
        super().__init__(entry.runtime_data.coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = device_info(entry)

    @property
    def native_value(self) -> datetime | None:
        """Return the expiry time."""
        return self.coordinator.data
