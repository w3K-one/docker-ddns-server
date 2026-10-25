# Dynamic DNS Server for Docker with Web UI written in Go

![Build status](https://img.shields.io/github/actions/workflow/status/w3K-one/docker-ddns-server/BuildEmAll.yml)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/w3K-one/docker-ddns-server)
![Go version](https://img.shields.io/github/go-mod/go-version/w3K-one/docker-ddns-server?filename=dyndns%2Fgo.mod)
![License](https://img.shields.io/github/license/w3K-one/docker-ddns-server)

With docker-ddns-server you can set up your own dynamic DNS server. This project is inspired by https://github.com/dprandzioch/docker-ddns. In addition to the original version, you can setup and maintain your dyndns entries via a simple web UI with comprehensive security features, modern authentication, and threat monitoring.

<p float="left">
<img src="https://raw.githubusercontent.com/w3K-one/docker-ddns-server/master/img/login.png" width="285">
<img src="https://raw.githubusercontent.com/w3K-one/docker-ddns-server/master/img/listhosts.png" width="285">
<img src="https://raw.githubusercontent.com/w3K-one/docker-ddns-server/master/img/addhost.png" width="285">
<img src="https://raw.githubusercontent.com/w3K-one/docker-ddns-server/master/img/listcnames.png" width="285">
<img src="https://raw.githubusercontent.com/w3K-one/docker-ddns-server/master/img/addcname.png" width="285">
<img src="https://raw.githubusercontent.com/w3K-one/docker-ddns-server/master/img/listlogs.png" width="285">
<img src="https://raw.githubusercontent.com/w3K-one/docker-ddns-server/master/img/security.png" width="285">
<img src="https://raw.githubusercontent.com/w3K-one/docker-ddns-server/master/img/logout.png" width="285">
</p>

## ✨ Key Features

- **Web-Based Management** - Compact icon navigation, left-aligned hostnames, sortable Hostname/IP/TTL/LastUpdate columns with an original-order reset and an All domains/per-zone filter, responsive host rows and certificate actions with accessible labels and tooltips
- **DNS Records** - A, AAAA, CNAME, TXT, MX, SRV, CAA and delegated NS RRsets
- **Dual-Stack DDNS** - Independent IPv4 and IPv6 client updates
- **Let’s Encrypt Certificates** - Automatic zone wildcard issuance and renewal, dedicated host certificates, and ZIP/PEM downloads
- **Security & IP Blocking** - Automatic protection against brute-force attacks
- **Modern Authentication** - Session-based admin login with HTTPS support
- **Security Dashboard** - Real-time monitoring of threats and blocked IPs
- **Multi-Platform Support** - Runs on amd64, arm64, arm (Raspberry Pi compatible)
- **Automatic Migration** - Handles legacy data with automatic normalization
- **Reverse Proxy Ready** - Works seamlessly with nginx, Caddy, Traefik
- **Threat Intelligence** - Comprehensive logging for attack pattern analysis

---

## DNS records and certificates (v2.1.0)

The **DNS records** icon opens static RRset management for A, AAAA, CNAME, TXT, MX,
SRV, CAA and delegated NS records. Select a managed zone, use `@` for its root,
and enter one value per line. Saving replaces that name/type's complete RRset;
other record types are preserved. TXT is entered without surrounding quotes;
long strings are split into DNS character strings automatically. MX uses
`10 mail.example.net`, SRV uses `10 5 443 service.example.net` at `_service._tcp`,
and CAA uses `0 issue letsencrypt.org`. NS records are for subzone delegation;
apex NS and SOA remain owned by BIND setup. In-zone MX/NS targets need valid
address/glue records before BIND accepts the delegation or mail routing.

Existing DDNS addresses and host-linked CNAMEs remain on their original pages.
Static records cannot overwrite their address/alias RRsets. Hosts can have TXT,
MX and other non-conflicting records; deleting a host preserves those records.
All four legacy update endpoints still accept IPv4 for A and IPv6 for AAAA.
A dual-stack client sends one request per address family; neither erases the other.

### Automatic zone certificates, dedicated host certificates

Open **Certificates → Automatic certificates**, enter a contact email, choose
RSA-2048 or EC P-256, accept the CA subscriber agreement and enable the policy.
The app maintains **one certificate containing the apex and wildcard per managed
zone**. A one-minute scheduler issues missing zone certificates serially and
renews opted-in certificates within 30 days of expiry (or after two-thirds of
their lifetime for short-lived certificates). Failed attempts back off
from one hour to 24 hours. Removing a managed zone stops its automatic renewals.
Disabling automatic issuance leaves existing certificates' renewal settings intact.
Certificate automation starts disabled until that one-time setup is completed.

For client infrastructure, use **Issue** on the host row or **New certificate**
with that single hostname. Automatic renewal is selected by default. The host row
then offers a **download icon**, containing `cert.pem`, `chain.pem`, `fullchain.pem` and
`privkey.pem`. **Host ZIP links never fall back to zone wildcards or multi-name
certificates**, and never select staging certificates. Wildcard ZIPs remain
available only from the admin Certificates page for the operator's own use.
All certificate endpoints require an authenticated admin session.

The Certificates page also provides individual PEM downloads, manual renewal /
reissue (with a fresh private key), revocation and an activity history. Failed
renewals preserve the previous certificate/key until replacement succeeds.
Downloads require HTTPS, are marked `no-store`, and are audited. Devices still
need their renewed certificate/key installed separately; this release does not
push certificates to gateways or add a public certificate download API.

DNS-01 uses exact-value TXT updates, preserving unrelated TXT and concurrent
apex/wildcard challenge values. Interrupted challenges are journaled for cleanup.
Names must be within `DDNS_DOMAINS`; public delegation must reach this BIND server,
and any CAA policy must permit Let's Encrypt. Authoritative NS checks normally
use public DNS; an explicit authoritative endpoint can be configured below.

### Optional configuration and key backups

No new required environment variable is introduced. Certificate and account keys
are encrypted with AES-256-GCM. On first use of this release, a separate random
key is persisted as `/root/database/cert.key` with mode 0600, alongside the SQLite
DB on the existing volume. **Back up the whole database volume, including
`cert.key`**. Losing that file makes stored private keys unrecoverable. Restoring
an existing certificate database without its key disables certificate features
rather than silently creating a replacement key. DNS continues operating if
certificate setup fails.

| Variable | Purpose |
|---|---|
| `DDNS_ACME_EMAIL` | Prefills the certificate contact email |
| `DDNS_CERT_KEY` | Optional 64-character hexadecimal encryption key instead of the persisted key file; keep stable and back it up |
| `DDNS_ACME_DIRECTORY` | Optional fixed ACME directory override, primarily for isolated Pebble tests; overrides the staging checkbox |
| `DDNS_ACME_AUTHORITATIVE_NS` | Optional authoritative DNS server, with optional port, for direct TXT propagation checks |
| `DDNS_ACME_RESOLVERS` | Optional comma-separated recursive resolver endpoints for ACME DNS lookup |
| `DDNS_TRUSTED_PROXIES` | Exact reverse-proxy IPs/CIDRs permitted to report HTTPS/client-IP headers; necessary for HTTPS downloads behind a proxy |
| `DDNS_ALLOW_INSECURE_DOWNLOAD` | `true` only in isolated LAN tests; default false |

Do not change `DDNS_CERT_KEY` or the persisted key file without re-encrypting the
stored keys. The session-cookie secret is separate and does not encrypt certificates.
For production updates use Chimera; preserve the existing database and BIND volumes.
Do not remove the existing acme.sh jobs until their clients have migrated.

### Verification

```sh
cd dyndns && go test -race ./... && go vet ./...
cd ..
docker build -f deployment/Dockerfile -t ddns-features-test:local .
python3 tests/m0_smoke.py ddns-features-test:local
python3 tests/features_smoke.py ddns-features-test:local
```

The feature smoke test creates disposable BIND and Pebble containers, uses fixture
credentials, and verifies actual DNS-01 issuance, EC/RSA wildcard+apex certificates,
renewal/key rotation, revocation and downloads. It never contacts Let's Encrypt
production. `--keep` leaves a local preview running until Enter is pressed.

---

## 📦 Installation

You can either use the pre-built Docker image or build it yourself.

### Using the Docker Image

Docker Hub: https://hub.docker.com/r/w3kllc/ddns

Generate a persistent secret first and store it securely for future deployments:

```bash
export DDNS_SESSION_SECRET="$(openssl rand -base64 32)"
```

**Quick Start:**
```bash
docker run -it -d \
    -p 8080:8080 \
    -p 53:53 \
    -p 53:53/udp \
    -v /somefolder:/var/cache/bind \
    -v /someotherfolder:/root/database \
    -e 'DDNS_ADMIN_LOGIN=admin:$2y$05$...' \
    -e DDNS_DOMAINS=dyndns.example.com \
    -e DDNS_PARENT_NS=ns.example.com \
    -e DDNS_DEFAULT_TTL=3600 \
    -e DDNS_SESSION_SECRET="$DDNS_SESSION_SECRET" \
    --name=dyndns \
    w3kllc/ddns:latest
```

### Using docker-compose (Recommended)

For a complete setup example, see: [docker-compose.yml](https://github.com/w3K-one/docker-ddns-server/blob/master/deployment/docker-compose.yml)

**Example docker-compose.yml:**
```yaml
version: '3.8'

services:
  ddns:
    image: w3kllc/ddns:latest
    container_name: dyndns
    ports:
      - "8080:8080"
      - "53:53"
      - "53:53/udp"
    volumes:
      - ./bind:/var/cache/bind
      - ./database:/root/database
      - ./static:/app/static  # Optional: for custom logo
    environment:
      # Required
      - DDNS_ADMIN_LOGIN=admin:$$2y$$05$$hashed_password_here
      - DDNS_DOMAINS=dyndns.example.com
      - DDNS_PARENT_NS=ns.example.com
      - DDNS_DEFAULT_TTL=3600
      
      # Required session signing secret
      - DDNS_SESSION_SECRET=${DDNS_SESSION_SECRET:?Set a persistent secret of at least 32 bytes}
      
      # Optional
      - DDNS_TITLE=My DynDNS Server
      - DDNS_CLEAR_LOG_INTERVAL=30
      - DDNS_ALLOW_WILDCARD=true
      - DDNS_LOGOUT_URL=https://example.com
      - DDNS_POWERED_BY=ACME Inc
      - DDNS_POWERED_BY_URL=https://acme.inc
    restart: unless-stopped
```

---

## ⚙️ Configuration

### Environment Variables

#### Required Variables

**`DDNS_ADMIN_LOGIN`**  
Admin credentials in htpasswd format for web UI access.

Generate with:
```bash
htpasswd -nb username password
```

For docker-compose.yml (escape dollar signs):
```bash
echo $(htpasswd -nb username password) | sed -e s/\\$/\\$\\$/g
```

If not set, all `/@/` routes are accessible without authentication (useful with auth proxy).

**`DDNS_DOMAINS`**  
Comma-separated list of domains managed by the server.  
Example: `dyndns.example.com,dyndns.example.org`

**`DDNS_PARENT_NS`**  
Parent nameserver of your domain.  
Example: `ns.example.com`

**`DDNS_DEFAULT_TTL`**  
Default TTL (Time To Live) for DNS records in seconds.  
Example: `3600` (1 hour)

#### Required Session Secret

**`DDNS_SESSION_SECRET`**  
Persistent secret for signing session cookies. **At least 32 bytes are required**; startup fails if it is missing or too short.

Generate with:
```bash
# Linux/Mac
openssl rand -base64 32

# Or using Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Keep the same value across container restarts. Changing it invalidates existing sessions. This is separate from the certificate encryption key.

#### Optional Variables

**`DDNS_TITLE`**  
Custom site title displayed in the web UI.  
Default: `"w3K DynDNS"`

**`DDNS_CLEAR_LOG_INTERVAL`**  
Automatically clear log entries older than specified days.  
Example: `30` (keep 30 days of logs)

**`DDNS_ALLOW_WILDCARD`**  
Enable wildcard DNS resolution (e.g., `*.subdomain.dyndns.example.com`).  
Values: `true` or `false`

**`DDNS_LOGOUT_URL`**  
Redirect to this URL after logout.  
Example: `https://example.com`

**`DDNS_POWERED_BY`**  
Show this in the footer credits.  
Example: `ACME Inc`

**`DDNS_POWERED_BY_URL`**  
The URL to _ACME Inc_.  
Example: `https:/acme.inc`

---

## 🌐 DNS Setup

If your parent domain is `example.com` and you want your DynDNS domain to be `dyndns.example.com`, your DynDNS hosts would be like `blog.dyndns.example.com`.

Add these entries to your parent DNS server:

```
dyndns                   IN NS      ns
ns                       IN A       <IPv4 address of your DynDNS server>
ns                       IN AAAA    <IPv6 address of your DynDNS server> (optional)
```

**Example:**
```
dyndns                   IN NS      ns
ns                       IN A       203.0.113.10
ns                       IN AAAA    2001:db8::10
```

---

## 🔐 Security Features

### IP Blocking & Threat Protection

- **Automatic IP Blocking**: IPs are blocked after 3 failed authentication attempts within 72 hours
- **7-Day Block Duration**: Blocked IPs are automatically unblocked after 7 days
- **Failed Authentication Logging**: Comprehensive logs including IP, timestamp, username, and password
- **Threat Intelligence**: Analyze attack patterns and password attempts
- **Manual Unblock**: Security dashboard allows manual IP unblocking
- **Automatic Cleanup**: Expired blocks and old logs are cleaned up automatically

### Session-Based Authentication

- **Modern Login Page**: No browser popup dialogs
- **Secure Sessions**: HttpOnly, Secure, and SameSite cookie attributes
- **Remember Me**: Optional 30-day session duration
- **Proper Logout**: Destroys sessions completely
- **HTTPS Enforcement**: Automatic redirect to HTTPS when available
- **Reverse Proxy Support**: Detects SSL via headers from explicitly trusted proxies

### Security Dashboard

Access the security dashboard at `/@/security` to:
- Monitor blocked IPs and active threats
- Review failed authentication attempts
- Analyze password patterns in attack attempts
- Manually unblock IP addresses
- View statistics and historical data

**Password Logging Rationale:**  
This is a single-user system where the admin is the only legitimate user. All other login attempts are malicious by definition. Password logging enables threat intelligence analysis to determine if attackers are getting close to your actual password. Ensure your database volume is properly secured.

---

## 🖥️ Admin Panel Access

The admin panel is accessible at `/@/` (not `/admin/` - more unique, less common).

### Main Features

- 🏠 **Dashboard** (`/@/`) - Overview and quick access
- 📝 **Hosts** (`/@/hosts`) - Manage DNS hosts with automatic lowercase migration
- 🔗 **CNAMEs** (`/@/cnames`) - Manage CNAME records
- **DNS records** (`/@/records`) - Manage static RRsets
- **Certificates** (`/@/certs`) - Configure automatic issuance, issue host certificates, and download packages
- 📊 **Logs** (`/@/logs`) - View update history
- 🔒 **Security** (`/@/security`) - Monitor threats and blocked IPs
- ⏏️ **Logout** (`/@/logout`) - End session securely

### Authentication Flow

1. Navigate to `/@/` (or any admin route)
2. Redirected to `/@/login` if not authenticated
3. Enter admin credentials
4. Optionally check "Remember Me" for 30-day session
5. Access admin panel
6. Click logout icon (⏏️) when done

**HTTPS Detection:**  
If running behind a reverse proxy with SSL, the system automatically detects HTTPS and enforces it for the admin panel while keeping API endpoints accessible via HTTP for device compatibility.

---

## 🔄 Updating DNS Entries

After adding a host via the web UI, configure your router or device to update its IP address.

### Update URLs

The server accepts updates on multiple endpoints:
- `/update`
- `/nic/update`
- `/v2/update`
- `/v3/update`

### With IP Address Specified

```
http://dyndns.example.com:8080/update?hostname=blog.dyndns.example.com&myip=1.2.3.4
```

Or with authentication in URL:
```
http://username:password@dyndns.example.com:8080/update?hostname=blog.dyndns.example.com&myip=1.2.3.4
```

### IPv6 and Dual-Stack Updates

Send an IPv6 address in `myip` to update AAAA:

```bash
curl -u username:password \
  "https://dyndns.example.com/nic/update?hostname=blog.dyndns.example.com&myip=2001:db8::10"
```

For dual-stack hosts, send a separate request with the IPv4 address to update A.
Each request changes only its own address family. All four update endpoints
support both families; no separate AAAA endpoint is needed.

### Without IP Address (Auto-detect)

If your router/device doesn't support sending the IP address (e.g., OpenWRT), omit the `myip` parameter:

```
http://dyndns.example.com:8080/update?hostname=blog.dyndns.example.com
```

Or with authentication:
```
http://username:password@dyndns.example.com:8080/update?hostname=blog.dyndns.example.com
```

The server automatically uses the client address from the request. Forwarded client addresses are accepted only from configured `DDNS_TRUSTED_PROXIES`; otherwise the immediate peer address is used. Send `myip` explicitly when a proxy cannot reliably convey the client’s address family.

### Authentication

API endpoints use **HTTP Basic Authentication** with the username and password you set for each host in the web UI (not the admin credentials).

**Important:** 
- **Admin credentials** (`DDNS_ADMIN_LOGIN`) - For web UI access at `/@/`
- **Host credentials** - For API updates, set per-host in the web UI

---

## 🎨 UI/UX Features

### Automatic Logo Detection

Place a logo file in the static directory to automatically display it:

**Supported formats:**
- `static/icons/logo.png`
- `static/icons/logo.webp`
- `static/icons/logo.svg`

If no logo is found, the system displays the text title (`DDNS_TITLE`).

**Docker volume mount for custom logo:**
```yaml
volumes:
  - ./static:/app/static
```

Then place your logo at: `./static/icons/logo.png`

### Visual Improvements

- **Sticky Header**: Navigation remains visible while scrolling
- **Unicode Icons**: 🏠 Dashboard, 🔒 Security, ⏏️ Logout (with tooltips)
- **Modern Design**: Clean, professional interface
- **HTTPS Indicator**: Visual confirmation of secure connection on login page
- **Password Controls**: Hide/reveal functionality with confirmation prompts
- **Responsive Layout**: Works on desktop, tablet, and mobile

---

## 🔧 Data Management

### Automatic Hostname Normalization

All usernames and hostnames are automatically converted to lowercase to prevent case-sensitivity issues:
- Database storage is always lowercase
- Lookups are case-insensitive
- Prevents duplicate entries with different cases

### Legacy Data Migration

When accessing `/@/hosts` for the first time, the system automatically migrates any uppercase entries:
- Converts hostnames to lowercase
- Handles conflicts by appending numbers (e.g., `host-1`, `host-2`)
- Displays migration report in the UI
- One-time process, status persisted in database
- Non-destructive, preserves all host data

### Username Flexibility

- **Non-Unique Usernames**: Multiple hosts can share the same username
- Enables flexible credential management strategies
- Each host can have the same or different password

### Validation Rules

- **Hostnames**: Minimum 1 character (allows single-letter subdomains)
- **Usernames**: Minimum 1 character
- **Passwords**: Minimum 6 characters

---

## 🔀 Reverse Proxy Configuration

The application intelligently detects HTTPS availability and adjusts behavior accordingly.

### HTTPS Detection Methods

Set `DDNS_TRUSTED_PROXIES` to the exact IPs/CIDRs of your reverse proxies as seen
by the container. Forwarded headers are ignored from other peers. Certificate
downloads require HTTPS even when other admin pages allow HTTP fallback.


1. Direct TLS connection (`request.TLS`)
2. `X-Forwarded-Proto` header
3. `X-Forwarded-Ssl` header
4. `X-Url-Scheme` header

### Behavior

**Admin Panel (`/@/*`):**
- Auto-redirects to HTTPS when available
- Graceful HTTP fallback if HTTPS unavailable
- Session cookies use Secure flag with HTTPS

**API Endpoints (`/update`, `/nic/update`, etc.):**
- Always accept HTTP connections
- No forced HTTPS redirect (device compatibility)
- Works with devices that don't support HTTPS

### Example Nginx Configuration

```nginx
server {
    listen 443 ssl;
    server_name dyndns.example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # Recommended SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Optional: HTTP to HTTPS redirect
server {
    listen 80;
    server_name dyndns.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Example Caddy Configuration

```
dyndns.example.com {
    reverse_proxy localhost:8080
}
```

Caddy automatically handles SSL certificates and sets appropriate headers.

---

## 🐳 Multi-Platform Docker Support

### Automated Builds

Docker images are automatically built via GitHub Actions for multiple platforms:

**Supported Platforms:**
- `linux/amd64` - Intel/AMD 64-bit (standard servers, PCs)
- `linux/386` - Intel/AMD 32-bit (older systems)
- `linux/arm/v7` - ARM 32-bit (Raspberry Pi 2/3, older ARM devices)
- `linux/arm64` - ARM 64-bit (Raspberry Pi 4+, modern ARM servers)

### Version Tags

Docker images are tagged using semantic versioning:

**`:latest`** - Always points to the most recent stable build

**`:vX.Y.Z`** - Semantic version tags (e.g., `:v1.2.3`)
- Version from commit message (if commit starts with `vX.Y.Z`)
- OR auto-incremented from last git tag
- OR date-based tag if no version tags exist

**Example:**
```bash
# Pull latest version
docker pull w3kllc/ddns:latest

# Pull specific version
docker pull w3kllc/ddns:v1.2.3

# Pull specific platform
docker pull --platform linux/arm64 w3kllc/ddns:latest
```

### Versioning Strategy

The build system automatically determines version tags using this priority order:

1. **Commit Message Version** (Highest Priority): If your commit message title starts with `vX.Y.Z` (e.g., `v1.2.3`), that exact version is used
2. **Auto-Increment from Last Tag**: If no version in commit message, finds the latest git tag and increments the patch version (e.g., `v1.2.3` → `v1.2.4`)
3. **Date-Based Fallback**: If no git tags exist at all, uses timestamp format `vYY.MM.DD-HHMM` (e.g., `v25.10.11-1430`)

**Example commit messages:**
```bash
# Explicit version (workflow extracts "v1.3.0" from start of commit message)
git commit -m "v1.3.0 Add new security features"

# Auto-increment (no version found, so increments last tag: v1.2.3 → v1.2.4)
git commit -m "Fix bug in authentication"

# Date-based (no tags exist yet, uses timestamp: v25.10.11-1430)
git commit -m "Initial release"
```

**How version extraction works:**
- Workflow searches for pattern `vX.Y.Z` or `vX.Y` at the **start** of commit message
- Must begin with `v` followed by numbers and dots
- Examples that work: `v1.0.0`, `v2.1.3`, `v1.2`
- Examples that won't work: `version 1.0.0` (missing `v`), `Release v1.0.0` (doesn't start with `v`)

### GitHub Releases

Each build automatically creates a GitHub release with:
- Version tag
- Docker image reference
- Commit message as release notes
- Source code archives (zip and tar.gz)

---

## 🚀 Migration from Original Project

If migrating from `dprandzioch/docker-ddns` or older versions of this fork:

### Before Migration

1. **Backup your data:**
   ```bash
   docker cp dyndns:/root/database ./backup-database
   docker cp dyndns:/var/cache/bind ./backup-bind
   ```

2. **Note your current configuration** (environment variables)

### Breaking Changes

1. **Admin Panel URL**: Changed from `/admin` to `/@/`
   - Update bookmarks and links
   - Use `/@/login` for login page

2. **Authentication Method**: Admin panel now uses sessions
   - Add `DDNS_SESSION_SECRET` environment variable
   - Login via web form instead of browser popup

3. **Required Variable**: `DDNS_SESSION_SECRET`
   - Required at startup, with at least 32 bytes; preserve it across restarts
   - Generate: `openssl rand -base64 32`

### Migration Steps

1. **Update docker-compose.yml** or docker command with new variables
2. **Add `DDNS_SESSION_SECRET`** to environment
3. **Update bookmarks** from `/admin` to `/@/`
4. **Restart container** with new configuration
5. **Visit `/@/hosts`** to trigger automatic data migration
6. **Review security dashboard** for any blocked IPs

### Backward Compatibility

✅ **Fully Compatible:**
- DynDNS API endpoints unchanged
- HTTP Basic Auth still works for device updates
- Existing host configurations work without changes
- Database schema additions are non-breaking
- All original functionality preserved

⚠️ **Manual Update Required:**
- Bookmark/link updates for admin panel
- Addition of a persistent session secret (required)

---

## 🔍 Troubleshooting

### Login Issues

**Problem:** Login redirects back to login page  
**Solution:** Preserve `DDNS_SESSION_SECRET` across restarts and verify proxy HTTPS detection.

**Problem:** Container exits with `DDNS_SESSION_SECRET must contain at least 32 bytes`
**Solution:** Generate a secret with `openssl rand -base64 32`, store it in your deployment environment, and recreate the container with that persistent value.

**Problem:** Can't remember admin password  
**Solution:** Regenerate password with `htpasswd -nb username newpassword` and update `DDNS_ADMIN_LOGIN`

### HTTPS Issues

**Problem:** HTTPS redirect loop  
**Solution:** Verify the reverse proxy sends `X-Forwarded-Proto: https` and its source IP is listed in `DDNS_TRUSTED_PROXIES`

**Problem:** "Not Secure" warning  
**Solution:** Check SSL certificate configuration in your reverse proxy

### IP Blocking

**Problem:** Locked out after failed login attempts  
**Solution:** 
- Wait 7 days for automatic unblock
- OR manually remove from `blocked_ips` table in database
- OR access database with SQLite: `DELETE FROM blocked_ips WHERE ip_address='YOUR_IP';`

### API Updates

**Problem:** Device updates not working  
**Solution:** 
- API uses host credentials (from web UI), not admin credentials
- Check username/password for specific host in `/@/hosts`
- Verify device is sending correct Basic Auth headers

**Problem:** "nochg" response from server  
**Solution:** IP address hasn't changed, this is normal behavior

### Build Issues

**Problem:** `missing go.sum entry for gorilla/sessions`  
**Solution:** 
```bash
go get github.com/gorilla/sessions@v1.2.2
go mod tidy
```

### Database Issues

**Problem:** Database locked errors  
**Solution:** Ensure only one container instance is running

**Problem:** Lost all data after update  
**Solution:** Check volume mounts are correct in docker-compose.yml

---

## 🛡️ Security Best Practices

1. **Always Set Session Secret**  
   Generate a strong random secret: `openssl rand -base64 32`

2. **Use HTTPS with Reverse Proxy**  
   Never expose the admin panel over plain HTTP in production

3. **Secure Database Volume**  
   Set appropriate file permissions:
   ```bash
   chmod 700 /path/to/database
   ```

4. **Regular Updates**  
   Keep Docker image updated: `docker pull w3kllc/ddns:latest`

5. **Monitor Security Dashboard**  
   Check `/@/security` regularly for attack patterns

6. **Strong Admin Password**  
   Use a password manager to generate and store strong credentials

7. **Separate Credentials**  
   Use different passwords for admin and each host

8. **Firewall Configuration**  
   Limit access to web UI (port 8080) to trusted networks if possible

9. **Database Backups**  
   Regularly backup the database volume

10. **Password Logging Awareness**  
    Remember that failed auth logs include passwords - secure your database

---

## 📚 API Reference

### Update Endpoints

All endpoints accept the same parameters:

**Endpoints:**
- `GET /update`
- `GET /nic/update`
- `GET /v2/update`
- `GET /v3/update`

**Parameters:**
- `hostname` (required) - Fully qualified domain name to update
- `myip` (optional) - IP address to set (auto-detected if omitted)

**Authentication:**
- HTTP Basic Auth using host credentials (username/password from web UI)

**Response Codes:**
- `good <IP>` - Update successful
- `nochg <IP>` - IP address hasn't changed
- `badauth` - Authentication failed
- `notfqdn` - Hostname is not a valid FQDN
- `nohost` - Hostname doesn't exist
- `abuse` - IP address has been blocked

**Example:**
```bash
curl -u username:password \
  "http://dyndns.example.com:8080/update?hostname=test.dyndns.example.com&myip=1.2.3.4"
```

---

## 🤝 Contributing

Contributions are welcome! Whether it's bug fixes, new features, documentation improvements, or reporting issues.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes**
4. **Test thoroughly**
5. **Commit your changes** (`git commit -m 'Add amazing feature'`)
6. **Push to your fork** (`git push origin feature/amazing-feature`)
7. **Open a Pull Request**

### Development Setup

```bash
# Clone the repository
git clone https://github.com/w3K-one/docker-ddns-server.git
cd docker-ddns-server

# Build the application
cd dyndns
go build

# Run tests (if available)
go test ./...

# Build Docker image locally
cd ..
docker build -t ddns:dev -f deployment/Dockerfile .
```

### Code Style

- Follow Go conventions and best practices
- Use `gofmt` for code formatting
- Add comments for complex logic
- Write meaningful commit messages

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Credits

**Original Project:**  
[dprandzioch/docker-ddns](https://github.com/dprandzioch/docker-ddns) - Original DynDNS server implementation

**Web UI Fork:**  
[benjaminbear/docker-ddns-server](https://github.com/benjaminbear/docker-ddns-server) - Added web UI for management

**Enhanced Fork:**  
[w3K-one/docker-ddns-server](https://github.com/w3K-one/docker-ddns-server) - Security features, modern auth, multi-platform support

### Major Enhancements in This Fork

- 🔒 IP blocking and threat protection system
- 🔐 Session-based authentication with modern login
- 📊 Security dashboard for monitoring attacks
- 🌐 HTTPS enforcement with reverse proxy support
- 🎨 Enhanced UI/UX with logo support and sticky header
- 📦 Multi-platform Docker builds (amd64, arm64, arm, 386)
- 🔄 Automatic data migration and normalization
- 📝 Comprehensive documentation
- 🤖 Automated CI/CD with GitHub Actions
- 🏷️ Semantic versioning with automatic releases

---

## 💬 Support

- **Issues:** [GitHub Issues](https://github.com/w3K-one/docker-ddns-server/issues)
- **Discussions:** [GitHub Discussions](https://github.com/w3K-one/docker-ddns-server/discussions)
- **Docker Hub:** [w3kllc/ddns](https://hub.docker.com/r/w3kllc/ddns)

---

## 🗺️ Roadmap

Potential future enhancements:
- Email notifications for security events
- Two-factor authentication (2FA)
- API rate limiting
- Web-based configuration wizard
- DNS over HTTPS (DoH) support
- Prometheus metrics export
- Docker Swarm / Kubernetes support
- Advanced search and filtering in logs
- Bulk host management

Have an idea? [Open an issue](https://github.com/w3K-one/docker-ddns-server/issues) or start a [discussion](https://github.com/w3K-one/docker-ddns-server/discussions)!

---

**Made with ❤️ by the community**
