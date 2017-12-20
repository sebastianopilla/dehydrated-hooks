# dehydrated-hooks
Hooks for the dehydrated Let's Encrypt client https://github.com/lukas2511/dehydrated using the Cloudflare and PowerDNS APIs.


### What is dehydrated?

dehydrated is a client for the ACME protocol which allows to acquire SSL certificates for web servers, mail servers, etc.

These hooks are executed by dehydrated when challenges need to be added or removed: the current implementations allow to deploy DNS challenges for domains served by [Cloudflare](https://api.cloudflare.com/) or by [PowerDNS](https://doc.powerdns.com/authoritative/http-api/index.html).

Download a release from GitHub or compile the project by yourself; instructions on how to operate with the 2 APIs are below.


### How to use the hooks

Prepare a shell script like the following:

```
#!/bin/sh

# collect arguments
COMMAND="${1}"
TARGET_HOSTNAME="${2}"
UNUSED="${3}"
TXT_RECORD_VALUE="${4}"

# full path to hooks jar
HOOKS_JAR="/usr/local/dehydrated-hooks/dehydrated-hooks.jar"

# full path to our configuration file which specifies the hook and its properties
CONFIGURATION_FILE="/etc/dehydrated/hooks/config"

# invoke the hook with our desired configuration and the given parameters
/usr/local/java/bin/java -jar "${HOOKS_JAR}" -config "${CONFIGURATION_FILE}" -command "${COMMAND}" -hostname "${TARGET_HOSTNAME}" -value "${TXT_RECORD_VALUE}"

```

then pass the script's path as the hook parameter to dehydrated.

### PowerDNS API Hook

Prepare a properties file with the following structure:

```
HOOK=powerdns

# endpoint and key for the PowerDNS API
PDNS_API_ENDPOINT=https://powerdns.example.com
PDNS_API_KEY=6Jo6763EneIIRE6CS8P3RWig

# how much time to wait before polling the nameservers, to allow the challenge records to be propagated
DNS_PROPAGATION_WAIT_SECS=120

# timeout for querying the authoritative nameservers
# give up if this time has passed and not all nameservers have the updated record
DNS_RESOLUTION_TIMEOUT_SECS=30

# use OpenDNS public resolver
DNS_RESOLVER=208.67.222.222
```

You will definitely have to change the `PDNS_API_ENDPOINT` to point to where your PowerDNS server API is configured, and `PDNS_API_KEY` to the API key which allows you to update records.

You don't need to change the other properties, unless you want to fine tune the timeouts for propagating challenge records across all of your nameservers, or if you want to use a different DNS resolver.


### Cloudflare API hook

Prepare a properties file with the following structure:

```
HOOK=cloudflare

# endpoint, login and key for the Cloudflare API
CLOUDFLARE_API_ENDPOINT=https://api.cloudflare.com/client/v4
CLOUDFLARE_API_EMAIL=me@example.com
CLOUDFLARE_API_KEY=M0UNn2CV69S116s2NPVW1onj67vGoW3iMQ4z

# how much time to wait before polling the nameservers, to allow the challenge records to be propagated
DNS_PROPAGATION_WAIT_SECS=60

# timeout for querying the authoritative nameservers
# give up if this time has passed and not all nameservers have the updated record
DNS_RESOLUTION_TIMEOUT_SECS=30

# use OpenDNS public resolver
DNS_RESOLVER=208.67.222.222
```

You will definitely have to change the `CLOUDFLARE_API_EMAIL` and `CLOUDFLARE_API_KEY` values to your own Cloudflare login and API key.

You don't need to change the other properties, unless you want to fine tune the timeouts for propagating challenge records across all of your nameservers, or if you want to use a different DNS resolver.
