"""Keep the Home Assistant certificate in sync with cPanel."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
import os
from pathlib import Path
import ssl
import tempfile

from cryptography import x509

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import (
    Certificate,
    CpanelAuthError,
    CpanelClient,
    CpanelError,
    async_call_webcall,
)
from .const import (
    AUTOSSL_NUDGE_THRESHOLD,
    CERT_FILENAME,
    CONF_DOMAIN,
    CONF_UPDATE_INTERVAL,
    CONF_WEBCALL_URL,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    KEY_FILENAME,
)

_LOGGER = logging.getLogger(__name__)

type CpanelSslConfigEntry = ConfigEntry[CpanelSslCoordinator]


@dataclass(frozen=True, slots=True)
class CertificateState:
    """What is currently installed."""

    expires: datetime
    cert_path: Path
    key_path: Path


def _default_ssl_dir(hass: HomeAssistant) -> Path:
    """Return /ssl on Home Assistant OS, otherwise <config>/ssl."""
    if (system_ssl := Path("/ssl")).is_dir():
        return system_ssl
    return Path(hass.config.path("ssl"))


def _atomic_write(path: Path, content: str, mode: int) -> Path:
    """Write content to a temp file next to path and return the temp path."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as file:
            file.write(content)
    except BaseException:
        os.unlink(tmp)
        raise
    return Path(tmp)


def _install_certificate(cert: Certificate, cert_path: Path, key_path: Path) -> bool:
    """Write the certificate if it changed; return True when files were replaced."""
    fullchain = cert.fullchain
    key = cert.key.strip() + "\n"
    try:
        if cert_path.read_text() == fullchain and key_path.read_text() == key:
            return False
    except FileNotFoundError:
        pass

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_cert = _atomic_write(cert_path, fullchain, 0o644)
    tmp_key = _atomic_write(key_path, key, 0o600)
    try:
        # Refuse to install a pair that would stop the HTTP server from starting.
        ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(
            tmp_cert, tmp_key
        )
        os.replace(tmp_key, key_path)
        os.replace(tmp_cert, cert_path)
    finally:
        tmp_cert.unlink(missing_ok=True)
        tmp_key.unlink(missing_ok=True)
    return True


class CpanelSslCoordinator(DataUpdateCoordinator[CertificateState]):
    """Fetch the certificate from cPanel and install it."""

    config_entry: CpanelSslConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: CpanelSslConfigEntry, client: CpanelClient
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(
                hours=entry.options.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL)
            ),
        )
        self.client = client
        self.domain: str = entry.data[CONF_DOMAIN]
        self.webcall_url: str | None = entry.options.get(CONF_WEBCALL_URL)
        self._webcall_failed = False

        http = hass.http
        if http.ssl_certificate and http.ssl_key:
            self.http_ssl_configured = True
            self.cert_path = Path(http.ssl_certificate)
            self.key_path = Path(http.ssl_key)
        else:
            self.http_ssl_configured = False
            ssl_dir = _default_ssl_dir(hass)
            self.cert_path = ssl_dir / CERT_FILENAME
            self.key_path = ssl_dir / KEY_FILENAME

    async def _async_update_data(self) -> CertificateState:
        """Fetch, install and reload the certificate."""
        try:
            cert = await self.client.fetch_certificate(self.domain)
        except CpanelAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except CpanelError as err:
            raise UpdateFailed(f"Error fetching certificate: {err}") from err

        try:
            expires = x509.load_pem_x509_certificate(
                cert.crt.encode()
            ).not_valid_after_utc
            changed = await self.hass.async_add_executor_job(
                _install_certificate, cert, self.cert_path, self.key_path
            )
        except (OSError, ValueError, ssl.SSLError) as err:
            raise UpdateFailed(f"Error installing certificate: {err}") from err

        if changed:
            _LOGGER.info(
                "Installed certificate for %s expiring %s", self.domain, expires
            )
            self._async_reload_http_certificate()

        if expires - dt_util.utcnow() < AUTOSSL_NUDGE_THRESHOLD:
            try:
                await self.client.start_autossl_check()
            except CpanelError as err:
                _LOGGER.debug("Could not start AutoSSL check: %s", err)

        return CertificateState(expires, self.cert_path, self.key_path)

    def _async_reload_http_certificate(self) -> None:
        """Load the new certificate into the running HTTP server."""
        if not self.http_ssl_configured:
            return
        # Runs in the event loop since handshakes read the context there and
        # OpenSSL does not lock certificate changes against them.
        if (context := getattr(self.hass.http, "context", None)) is not None:
            try:
                context.load_cert_chain(self.cert_path, self.key_path)
            except (OSError, ssl.SSLError) as err:
                _LOGGER.warning("Could not reload certificate: %s", err)
            else:
                return
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            "restart_required",
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="restart_required",
            translation_placeholders={"domain": self.domain},
        )

    async def async_update_dynamic_dns(self, raise_on_error: bool = False) -> None:
        """Call the Dynamic DNS webcall."""
        assert self.webcall_url is not None
        try:
            response = await async_call_webcall(
                async_get_clientsession(self.hass),
                self.webcall_url,
                self.client.verify_ssl,
            )
        except CpanelError as err:
            if raise_on_error:
                raise HomeAssistantError(f"Dynamic DNS update failed: {err}") from err
            if not self._webcall_failed:
                _LOGGER.warning("Dynamic DNS update failed: %s", err)
            self._webcall_failed = True
            return
        if self._webcall_failed:
            _LOGGER.info("Dynamic DNS update recovered")
        self._webcall_failed = False
        _LOGGER.debug("Dynamic DNS update response: %s", response)
