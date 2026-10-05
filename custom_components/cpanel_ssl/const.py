"""Constants for the cPanel SSL integration."""

from datetime import timedelta

DOMAIN = "cpanel_ssl"

CONF_DOMAIN = "domain"
CONF_WEBCALL_URL = "webcall_url"
CONF_UPDATE_INTERVAL = "update_interval"

DEFAULT_PORT = 2083
DEFAULT_UPDATE_INTERVAL = 12

# Ask AutoSSL to run when the cert we can see is this close to expiry.
AUTOSSL_NUDGE_THRESHOLD = timedelta(days=14)

CERT_FILENAME = "fullchain.pem"
KEY_FILENAME = "privkey.pem"
