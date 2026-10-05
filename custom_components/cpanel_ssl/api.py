"""Minimal client for the cPanel UAPI and Dynamic DNS webcalls."""

from dataclasses import dataclass
from typing import Any

import aiohttp

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
        verify_ssl: bool,
    ) -> None:
        """Initialize the client."""
        self._session = session
        self._base_url = f"https://{host}:{port}/execute"
        self._headers = {"Authorization": f"cpanel {username}:{token}"}
        self.verify_ssl = verify_ssl

    async def _uapi(self, module: str, function: str, **params: str) -> Any:
        """Call a UAPI function and return its data."""
        try:
            async with self._session.get(
                f"{self._base_url}/{module}/{function}",
                params=params,
                headers=self._headers,
                ssl=self.verify_ssl,
                timeout=REQUEST_TIMEOUT,
            ) as resp:
                if resp.status in (401, 403):
                    raise CpanelAuthError(f"cPanel returned HTTP {resp.status}")
                resp.raise_for_status()
                body = await resp.json(content_type=None)
        except (aiohttp.ClientError, TimeoutError, ValueError) as err:
            raise CpanelConnectionError(str(err) or type(err).__name__) from err

        result = body.get("result", body)
        if not result.get("status"):
            errors = result.get("errors") or ["unknown error"]
            raise CpanelApiError("; ".join(errors))
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


async def async_call_webcall(
    session: aiohttp.ClientSession, url: str, verify_ssl: bool
) -> str:
    """Call a Dynamic DNS webcall so cPanel records our public IP."""
    try:
        async with session.get(url, ssl=verify_ssl, timeout=REQUEST_TIMEOUT) as resp:
            resp.raise_for_status()
            return (await resp.text()).strip()
    except (aiohttp.ClientError, TimeoutError) as err:
        raise CpanelConnectionError(str(err) or type(err).__name__) from err
