# cPanel SSL for Home Assistant

Keeps the Home Assistant HTTPS certificate in sync with the one cPanel issues through AutoSSL, and can keep a cPanel Dynamic DNS record pointed at your home IP.

If your Home Assistant is reachable at a name hosted on a cPanel account (for example `home.example.com` set up under Domains, Dynamic DNS), cPanel already issues and renews a certificate for it. This integration copies that certificate to Home Assistant and loads it into the running web server, so renewals happen without a restart.

## How it works

* Every 12 hours (configurable) it asks cPanel for the best certificate for your hostname using the `SSL::fetch_best_for_domain` UAPI call.
* If the certificate changed, the full chain and private key are written to the paths in your `http:` configuration. The pair is verified before anything is replaced.
* The new certificate is loaded into the running HTTP server; new connections use it right away.
* When the certificate is within 14 days of expiry it asks cPanel to run AutoSSL.
* If you give it a Dynamic DNS webcall URL, it calls it every 5 minutes so cPanel keeps your IP current. This replaces a `rest_command` or router based updater.

## Installation

1. In HACS, open the menu, choose Custom repositories, and add `https://github.com/bdraco/ha-cpanel-ssl` as an Integration.
2. Install cPanel SSL and restart Home Assistant.
3. Go to Settings, Devices & services, Add integration, and pick cPanel SSL.

## Setup

You need:

* **cPanel host and port**: the name you use to log in to cPanel, usually on port 2083.
* **Username and API token**: create a token in cPanel under Security, Manage API Tokens.
* **Home Assistant hostname**: the name cPanel has a certificate for. It is prefilled from your external URL when one is set.
* **Dynamic DNS webcall URL** (optional): shown in cPanel under Domains, Dynamic DNS after you create the record. Treat it like a password.

### Serving HTTPS

If Home Assistant is already configured with `ssl_certificate` and `ssl_key`, those files are kept up to date.

If not, the certificate is saved to `/ssl/fullchain.pem` and `/ssl/privkey.pem` (or `<config>/ssl` when `/ssl` does not exist) and a repair tells you what to add:

```yaml
http:
  ssl_certificate: /ssl/fullchain.pem
  ssl_key: /ssl/privkey.pem
```

Restart once after adding it. Later renewals are loaded without a restart.

## Entities

* **Certificate expiry**: when the installed certificate expires.
* **Refresh certificate**: fetch from cPanel now.
* **Update IP**: call the Dynamic DNS webcall now (only when a webcall URL is set).

## Running more than one instance

Each Home Assistant install serves one certificate, so the integration is set up once per install. Point each install at its own hostname; one cPanel account can serve many.
