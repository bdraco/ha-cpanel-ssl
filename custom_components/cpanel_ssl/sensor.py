"""Certificate expiry sensor for cPanel SSL."""

from datetime import datetime

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import CpanelSslConfigEntry
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
    async_add_entities([CpanelSslExpirySensor(entry.runtime_data, EXPIRY_DESCRIPTION)])


class CpanelSslExpirySensor(CpanelSslEntity, SensorEntity):
    """When the installed certificate expires."""

    @property
    def native_value(self) -> datetime:
        """Return the expiry time."""
        return self.coordinator.data.expires
