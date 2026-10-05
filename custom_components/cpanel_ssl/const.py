"""Constants for the cPanel SSL integration."""

from datetime import timedelta

DOMAIN = "cpanel_ssl"

CONF_DOMAIN = "domain"
CONF_DYNAMIC_DNS = "dynamic_dns"
CONF_UPDATE_INTERVAL = "update_interval"

DEFAULT_PORT = 2083
DEFAULT_UPDATE_INTERVAL = 12

# Check more often while waiting for AutoSSL to issue a first certificate.
PENDING_CERTIFICATE_INTERVAL = timedelta(minutes=15)

# Ask AutoSSL to run when the cert we can see is this close to expiry.
AUTOSSL_NUDGE_THRESHOLD = timedelta(days=14)

CERT_FILENAME = "fullchain.pem"
KEY_FILENAME = "privkey.pem"
