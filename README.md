# cPanel SSL for Home Assistant

Keeps the Home Assistant HTTPS certificate in sync with the one cPanel issues through AutoSSL, and can keep a cPanel Dynamic DNS record pointed at your home IP.

If your Home Assistant is reachable at a name hosted on a cPanel account (for example `home.example.com`), cPanel AutoSSL issues and renews a certificate for it. This integration copies that certificate to Home Assistant and loads it into the running web server, so renewals happen without a restart.

## How it works

* Every 12 hours (configurable) it asks cPanel for the best certificate for your hostname using the `SSL::fetch_best_for_domain` UAPI call.
* If the certificate changed, the full chain and private key are written to the paths in your `http:` configuration. The pair is verified before anything is replaced.
* The new certificate is loaded into the running HTTP server; new connections use it right away.
* When the certificate is within 14 days of expiry it asks cPanel to run AutoSSL.
* With Manage Dynamic DNS on, it finds the cPanel Dynamic DNS record for your hostname, creates it if missing, and calls its webcall every 5 minutes so the IP stays current. This replaces a `rest_command` or router based updater.
* If AutoSSL has not issued a certificate yet, it asks AutoSSL to run and checks again every 15 minutes until one shows up.

## Installation

1. In HACS, open the menu, choose Custom repositories, and add `https://github.com/bdraco/ha-cpanel-ssl` as an Integration.
2. Install cPanel SSL and restart Home Assistant.
3. Go to Settings, Devices & services, Add integration, and pick cPanel SSL.

## Setup

You need:

* **cPanel host and port**: the name you use to log in to cPanel, usually on port 2083.
* **Username and API token**: create a token in cPanel under Security, Manage API Tokens.
* **Home Assistant hostname**: the name Home Assistant is reached at, for example `home.example.com`. It is prefilled from your external URL when one is set.
* **Manage Dynamic DNS**: on by default. Leave it on if your home IP changes; turn it off if the name already points somewhere else.

### Serving HTTPS

If Home Assistant already serves HTTPS, the certificate and key files it uses are kept up to date.

If not, the certificate is saved to `/ssl` (or `<config>/ssl` outside Home Assistant OS) and the integration sets those paths in the HTTP server settings, then restarts Home Assistant once. Home Assistant asks you to keep the new settings; if nobody confirms within a few minutes it switches back on its own and a repair explains how to set the paths yourself under Settings, System, Network.

Later renewals are loaded without a restart.

Requires Home Assistant 2026.8 or newer.

## Entities

* **Certificate expiry**: when the installed certificate expires.
* **Refresh certificate**: fetch from cPanel now.
* **Update IP**: call the Dynamic DNS webcall now (only when Manage Dynamic DNS is on).

## Running more than one instance

Each Home Assistant install serves one certificate, so the integration is set up once per install. Point each install at its own hostname; one cPanel account can serve many.
