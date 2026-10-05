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
from .entity import CpanelSslEntity

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


class CpanelSslExpirySensor(
    CoordinatorEntity[CpanelSslCoordinator], CpanelSslEntity, SensorEntity
):
    """When the installed certificate expires."""

    def __init__(
        self, entry: CpanelSslConfigEntry, description: SensorEntityDescription
    ) -> None:
        """Initialize the sensor."""
        CoordinatorEntity.__init__(self, entry.runtime_data.coordinator)
        CpanelSslEntity.__init__(self, entry, description)

    @property
    def native_value(self) -> datetime:
        """Return the expiry time."""
        return self.coordinator.data
