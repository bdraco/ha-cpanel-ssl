"""Keep the Home Assistant certificate in sync with cPanel."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from pathlib import Path
import ssl
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

from homeassistant.components.http.config import (
    HTTP_CONFIG_CREATED_AT,
    HTTP_CONFIG_ERROR,
    HTTP_CONFIG_ERROR_MESSAGE,
    ConfData,
    async_get_and_load_store,
)
from homeassistant.components.http.const import CONF_SSL_CERTIFICATE, CONF_SSL_KEY
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.hassio import is_hassio
from homeassistant.helpers.start import async_at_started
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util
from homeassistant.util.file import write_utf8_file

from .api import (
    Certificate,
    CpanelAuthError,
    CpanelClient,
    CpanelError,
    CpanelNoCertificateError,
)
from .const import (
    AUTOSSL_NUDGE_THRESHOLD,
    CERT_FILENAME,
    CONF_DOMAIN,
    CONF_UPDATE_INTERVAL,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    KEY_FILENAME,
    PENDING_CERTIFICATE_INTERVAL,
)
from .dynamic_dns import DynamicDnsUpdater

_LOGGER = logging.getLogger(__name__)

HTTP_CONFIG_META = (
    HTTP_CONFIG_CREATED_AT,
    HTTP_CONFIG_ERROR,
    HTTP_CONFIG_ERROR_MESSAGE,
)


@dataclass(slots=True)
class CpanelSslRuntimeData:
    """Runtime data for a config entry."""

    coordinator: CpanelSslCoordinator
    dynamic_dns: DynamicDnsUpdater | None


type CpanelSslConfigEntry = ConfigEntry[CpanelSslRuntimeData]


def _public_key_der(obj: x509.Certificate | PrivateKeyTypes) -> bytes:
    """Return the DER encoded public key of a certificate or private key."""
    return obj.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def _install_certificate(
    cert: Certificate, cert_path: Path, key_path: Path
) -> tuple[bool, datetime]:
    """Write the certificate if it changed; return (changed, expiry)."""
    leaf = x509.load_pem_x509_certificate(cert.crt.encode())
    private_key = load_pem_private_key(cert.key.encode(), password=None)
    # Refuse to install a pair that would stop the HTTP server from starting.
    if _public_key_der(leaf) != _public_key_der(private_key):
        raise ValueError("certificate does not match its private key")

    fullchain = cert.fullchain
    key = cert.key.strip() + "\n"
    expires = leaf.not_valid_after_utc
    try:
        if cert_path.read_text() == fullchain and key_path.read_text() == key:
            return False, expires
    except FileNotFoundError:
        pass

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    write_utf8_file(str(key_path), key, private=True)
    write_utf8_file(str(cert_path), fullchain)
    return True, expires


class CpanelSslCoordinator(DataUpdateCoordinator[datetime | None]):
    """Fetch the certificate from cPanel, install it and track its expiry.

    Data is the expiry, or None while AutoSSL has not issued a certificate yet.
    """

    config_entry: CpanelSslConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: CpanelSslConfigEntry, client: CpanelClient
    ) -> None:
        """Initialize the coordinator."""
        self._interval = timedelta(
            hours=entry.options.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL)
        )
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=self._interval,
        )
        self.client = client
        self._autossl_requested = False
        self._https_requested = False
        self.domain: str = entry.data[CONF_DOMAIN]

        http = hass.http
        if http.ssl_certificate and http.ssl_key:
            self.http_ssl_configured = True
            self.cert_path = Path(http.ssl_certificate)
            self.key_path = Path(http.ssl_key)
        else:
            self.http_ssl_configured = False
            ssl_dir = Path("/ssl") if is_hassio(hass) else Path(hass.config.path("ssl"))
            self.cert_path = ssl_dir / CERT_FILENAME
            self.key_path = ssl_dir / KEY_FILENAME

    async def _async_setup(self) -> None:
        """Clear a stale repair once HTTPS is on."""
        if self.http_ssl_configured:
            ir.async_delete_issue(self.hass, DOMAIN, "https_not_confirmed")

    async def _async_enable_https(self, _hass: HomeAssistant) -> None:
        """Stage the certificate in the HTTP config and restart to try it.

        Home Assistant asks the user to keep the new settings and reverts on
        its own if nobody confirms, so a bad switch cannot lock anyone out.
        """
        store = await async_get_and_load_store(self.hass)
        if (pending := store.pending) is not None:
            if (
                pending.get(CONF_SSL_CERTIFICATE) == str(self.cert_path)
                and pending[HTTP_CONFIG_ERROR]
            ):
                # Our trial was reverted; retrying would restart in a loop.
                ir.async_create_issue(
                    self.hass,
                    DOMAIN,
                    "https_not_confirmed",
                    is_fixable=False,
                    severity=ir.IssueSeverity.WARNING,
                    learn_more_url="homeassistant://config/network",
                    translation_key="https_not_confirmed",
                    translation_placeholders={
                        "cert_path": str(self.cert_path),
                        "key_path": str(self.key_path),
                    },
                )
                return
            if pending[HTTP_CONFIG_ERROR] is None:
                # Leave a trial the user staged alone.
                return

        config: dict[str, Any] = {
            key: value
            for key, value in store.stable.items()
            if key not in HTTP_CONFIG_META
        }
        config[CONF_SSL_CERTIFICATE] = str(self.cert_path)
        config[CONF_SSL_KEY] = str(self.key_path)
        _LOGGER.warning(
            "Restarting to serve the certificate for %s over HTTPS; confirm the"
            " new HTTP settings when asked or they revert in a few minutes",
            self.domain,
        )
        await store.async_set_pending(cast(ConfData, config))
        await self.hass.services.async_call("homeassistant", "restart")

    async def _async_start_autossl(self) -> None:
        """Ask cPanel to run AutoSSL once until a new certificate shows up."""
        if self._autossl_requested:
            return
        try:
            await self.client.start_autossl_check()
        except CpanelError as err:
            _LOGGER.debug("Could not start AutoSSL check: %s", err)
        else:
            self._autossl_requested = True

    async def _async_update_data(self) -> datetime | None:
        """Fetch, install and reload the certificate."""
        try:
            cert = await self.client.fetch_certificate(self.domain)
        except CpanelNoCertificateError:
            _LOGGER.info(
                "Waiting for AutoSSL to issue a certificate for %s", self.domain
            )
            await self._async_start_autossl()
            self.update_interval = PENDING_CERTIFICATE_INTERVAL
            return None
        except CpanelAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except CpanelError as err:
            raise UpdateFailed(f"Error fetching certificate: {err}") from err

        try:
            changed, expires = await self.hass.async_add_executor_job(
                _install_certificate, cert, self.cert_path, self.key_path
            )
        except (OSError, ValueError, TypeError, HomeAssistantError) as err:
            raise UpdateFailed(f"Error installing certificate: {err}") from err

        self.update_interval = self._interval
        if not self.http_ssl_configured and not self._https_requested:
            self._https_requested = True
            self.config_entry.async_on_unload(
                async_at_started(self.hass, self._async_enable_https)
            )
        if changed:
            self._autossl_requested = False
            _LOGGER.info(
                "Installed certificate for %s expiring %s", self.domain, expires
            )
            if self.http_ssl_configured:
                self._async_reload_http_certificate()

        if expires - dt_util.utcnow() < AUTOSSL_NUDGE_THRESHOLD:
            await self._async_start_autossl()

        return expires

    def _async_reload_http_certificate(self) -> None:
        """Load the new certificate into the running HTTP server."""
        # Only None in recovery mode, which a restart resolves anyway.
        if (context := self.hass.http.context) is None:
            return
        # Runs in the event loop since handshakes read the context there and
        # OpenSSL does not lock certificate changes against them.
        try:
            context.load_cert_chain(self.cert_path, self.key_path)
        except (OSError, ssl.SSLError) as err:
            _LOGGER.warning(
                "Could not load the new certificate, restart Home Assistant to use it: %s",
                err,
            )
