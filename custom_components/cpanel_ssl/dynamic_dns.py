"""Keep a cPanel Dynamic DNS record pointed at this network."""

from datetime import datetime, timedelta
import logging

from aiocpanel import CpanelClient, CpanelError, DynamicDnsRecord

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.event import async_track_time_interval

_LOGGER = logging.getLogger(__name__)

UPDATE_INTERVAL = timedelta(minutes=5)


class DynamicDnsUpdater:
    """Call the Dynamic DNS webcall on a timer."""

    def __init__(
        self, hass: HomeAssistant, client: CpanelClient, record: DynamicDnsRecord
    ) -> None:
        """Initialize the updater."""
        self._hass = hass
        self._client = client
        self._record = record
        self._failed = False

    async def async_update(self) -> None:
        """Call the webcall; raises CpanelError on failure."""
        response = await self._client.call_webcall(self._record)
        _LOGGER.debug("Dynamic DNS update response: %s", response)

    async def _async_scheduled_update(self, _now: datetime | None = None) -> None:
        """Update and log failures once per outage."""
        try:
            await self.async_update()
        except CpanelError as err:
            if not self._failed:
                _LOGGER.warning("Dynamic DNS update failed: %s", err)
            self._failed = True
            return
        if self._failed:
            _LOGGER.info("Dynamic DNS update recovered")
        self._failed = False

    def async_start(self, entry: ConfigEntry) -> None:
        """Update now and on an interval until the entry unloads."""
        entry.async_create_background_task(
            self._hass, self._async_scheduled_update(), "cpanel_ssl_dynamic_dns"
        )
        entry.async_on_unload(
            async_track_time_interval(
                self._hass, self._async_scheduled_update, UPDATE_INTERVAL
            )
        )
