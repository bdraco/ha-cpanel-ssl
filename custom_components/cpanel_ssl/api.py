"""Minimal client for the cPanel UAPI and Dynamic DNS webcalls."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import aiohttp

from homeassistant.const import (
    CONF_API_TOKEN,
    CONF_HOST,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.util.json import json_loads

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)


class CpanelError(Exception):
    """Base error for cPanel requests."""


class CpanelConnectionError(CpanelError):
    """cPanel could not be reached."""


class CpanelAuthError(CpanelError):
    """cPanel rejected the credentials."""


class CpanelApiError(CpanelError):
    """cPanel returned an error for the call."""


class CpanelNoCertificateError(CpanelError):
    """cPanel has no certificate for the domain."""


@dataclass(frozen=True, slots=True)
class Certificate:
    """A certificate, its key and the CA bundle."""

    crt: str
    key: str
    cab: str | None

    @property
    def fullchain(self) -> str:
        """Return the leaf certificate followed by the CA bundle."""
        parts = [self.crt.strip()]
        if self.cab:
            parts.append(self.cab.strip())
        return "\n".join(parts) + "\n"


class CpanelClient:
    """Talk to a single cPanel account."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        username: str,
        token: str,
    ) -> None:
        """Initialize the client."""
        self._session = session
        self._base_url = f"https://{host}:{port}/execute"
        self._headers = {"Authorization": f"cpanel {username}:{token}"}

    async def _get(self, url: str, **kwargs: Any) -> str:
        """GET a URL and return the body."""
        try:
            async with self._session.get(
                url, timeout=REQUEST_TIMEOUT, **kwargs
            ) as resp:
                if resp.status in (401, 403):
                    raise CpanelAuthError(f"cPanel returned HTTP {resp.status}")
                resp.raise_for_status()
                return await resp.text()
        except (aiohttp.ClientError, TimeoutError) as err:
            raise CpanelConnectionError(str(err) or type(err).__name__) from err

    async def _uapi(self, module: str, function: str, **params: str) -> Any:
        """Call a UAPI function and return its data."""
        body = await self._get(
            f"{self._base_url}/{module}/{function}",
            params=params,
            headers=self._headers,
        )
        try:
            response: Any = json_loads(body)
            result = response["result"]
        except (ValueError, KeyError, TypeError) as err:
            raise CpanelApiError(f"Unexpected response from cPanel: {err}") from err
        if not result.get("status"):
            raise CpanelApiError("; ".join(result.get("errors") or ["unknown error"]))
        return result.get("data")

    async def fetch_certificate(self, domain: str) -> Certificate:
        """Return the best installed certificate for a domain."""
        data = await self._uapi("SSL", "fetch_best_for_domain", domain=domain)
        if not data or not data.get("crt") or not data.get("key"):
            raise CpanelNoCertificateError(f"No certificate found for {domain}")
        return Certificate(crt=data["crt"], key=data["key"], cab=data.get("cab"))

    async def start_autossl_check(self) -> None:
        """Ask cPanel to run AutoSSL for the account."""
        await self._uapi("SSL", "start_autossl_check")

    async def call_webcall(self, url: str) -> str:
        """Call a Dynamic DNS webcall so cPanel records our public IP."""
        return (await self._get(url)).strip()


def async_create_client(hass: HomeAssistant, data: Mapping[str, Any]) -> CpanelClient:
    """Create a client from config entry data."""
    return CpanelClient(
        async_get_clientsession(hass, verify_ssl=data[CONF_VERIFY_SSL]),
        data[CONF_HOST],
        data[CONF_PORT],
        data[CONF_USERNAME],
        data[CONF_API_TOKEN],
    )
