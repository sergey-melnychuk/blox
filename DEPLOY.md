# Deploying the relay

How to run the public relay (`relay.example.com`, or your own host) on a Linux server: one
binary under systemd, Caddy in front for TLS, logs in the journal with rotation. For running
everything on your own computer, see [RUN.md](RUN.md). The relay itself is specified in
BLOX.md §8.

```
phones, sites ──HTTPS :443──▶ Caddy (TLS, certificates) ──HTTP localhost:8080──▶ blox-relay
                                   │                                                │
                                   └──────────── journald (rotated) ◀───────────────┘
```

- **blox-relay**: one binary with no files, no database and no state on disk. A
  restart drops queued messages, tickets and revocations, which is safe (BLOX.md §5.5).
  It runs as a throwaway user under a locked-down systemd unit.
- **Caddy** gets and renews the certificate, and is the only thing listening on the internet.
  The Caddyfile here has no access log (section 4).
- **Logs**: the relay logs only its start line by default, and at `debug` the route template,
  status and latency of each request. It never logs addresses, paths, tokens or bodies
  (BLOX.md §8.5).

Files in [`deploy/`](deploy/):

| File | Installed as |
|---|---|
| `blox-relay.service` | `/etc/systemd/system/blox-relay.service` |
| `relay.env` | `/etc/blox/relay.env` |
| `Caddyfile` | `/etc/caddy/Caddyfile` |
| `journald-blox.conf` | `/etc/systemd/journald.conf.d/blox.conf` |
| `Dockerfile` | only for the [Docker alternative](#docker-instead-of-systemd) |

Commands marked **(local)** run in the repository on your computer; the rest run on the server
as root (or with `sudo`).

## 1. Server

- Debian 12+ or Ubuntu 22.04+ (any Linux with systemd and glibc 2.34+), x86-64
  or arm64. 1 vCPU and 1 GB RAM is plenty.
- **DNS:** an `A` record (and `AAAA` if the server has IPv6) for the relay's host name
  pointing at the server. Caddy can only get a certificate once this resolves.
- **Firewall:** open TCP 80 (certificate challenges and the HTTPS redirect), TCP 443 and UDP
  443 (HTTP/3). Port 8080 stays closed; the relay listens on loopback anyway.
  ```sh
  ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp && ufw enable
  ```
- **The clock must be synced.** Request signatures and connection tokens are checked against
  the relay's time with 60 s of tolerance (BLOX.md §4.8):
  ```sh
  timedatectl                          # "System clock synchronized: yes"
  timedatectl set-ntp true             # if it isn't
  ```

## 2. Build

A release binary for the server's architecture (`uname -m`: `x86_64` or `aarch64`), linked
against glibc 2.34 or newer. Either of these:

- **On a Linux machine** of the same architecture whose glibc is no newer than the server's
  (`ldd --version | head -1` on both), with Rust 1.94+ and `build-essential`:
  ```sh
  cargo build --release --locked -p blox-relay      # target/release/blox-relay
  ```
- **On macOS**, cross-built with zig (`brew install zig`, `cargo install cargo-zigbuild`).
  The `.2.34` suffix sets the oldest glibc the binary runs on:
  ```sh
  rustup target add x86_64-unknown-linux-gnu          # or aarch64-unknown-linux-gnu
  cargo zigbuild --release --locked -p blox-relay --target x86_64-unknown-linux-gnu.2.34
  # target/x86_64-unknown-linux-gnu/release/blox-relay
  ```
  zig's "ignoring deprecated linker optimization setting" warning is harmless.

Not musl: its memory allocator is slow under the relay's multithreaded load. Building on the
server itself works too, but a 1 GB server runs out of memory.

## 3. Install the relay

Copy the binary and the deploy files (`HOST` is your server; a binary built on Linux is at
`target/release/blox-relay`):

```sh
HOST=root@relay.example.com
scp target/x86_64-unknown-linux-gnu/release/blox-relay \
    deploy/blox-relay.service deploy/relay.env deploy/Caddyfile deploy/journald-blox.conf \
    "$HOST":/tmp/
```

On the server:

```sh
install -m 0755 /tmp/blox-relay /usr/local/bin/blox-relay
install -d -m 0755 /etc/blox
install -m 0644 /tmp/relay.env /etc/blox/relay.env            # first install only; it's your config
install -m 0644 /tmp/blox-relay.service /etc/systemd/system/blox-relay.service
systemctl daemon-reload
systemctl enable --now blox-relay
systemctl status blox-relay --no-pager
curl -s http://localhost:8080/health                          # {"ok":true}
```

The journal should show `blox-relay started listen=localhost:8080 trust_proxy=true`
(`journalctl -u blox-relay -n 5`).

`relay.env` holds the settings: `BLOX_LISTEN` (loopback), **`BLOX_TRUST_PROXY=1`** (client
addresses for the per-IP limits come from the `X-Forwarded-For` entry Caddy adds), `BLOX_LOG`,
and commented-out limits. `blox-relay --help` lists every option. After changing it:
`systemctl restart blox-relay`.

`systemd-analyze security blox-relay` shows the hardening: the unit runs as a throwaway user
(`DynamicUser`), with a read-only system, no capabilities, IPv4/IPv6 sockets only, a system-call
filter, 1 GB of memory at most and 65,536 open files (one per waiting reader).

## 4. Caddy

Install Caddy from its official repository (it comes with a systemd unit, `caddy.service`,
that reads `/etc/caddy/Caddyfile`):

```sh
apt install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install -y caddy
```

Install the Caddyfile, **change the host name** in it if it isn't `relay.example.com`, and load it:

```sh
install -m 0644 /tmp/Caddyfile /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile        # "Valid configuration"
systemctl reload caddy
journalctl -u caddy -n 20 --no-pager                # "certificate obtained successfully"
```

What the Caddyfile does:

- `reverse_proxy localhost:8080` with **`flush_interval -1`**, so server-sent events (how
  phones and sites wait for messages) go through at once instead of being buffered.
- **No `log` directive in the site block**, so there is no access log. Adding one
  (`log { output file … }`) records each request's client address, URI (which holds the
  inbox id) and headers. The public instance at `relay.example.com` keeps such a log.
- The global `log` block excludes `http.log.error`, `http.handlers.reverse_proxy` and
  `http.stdlib`. Those loggers write the client address and the full URI (which holds an inbox
  id) when a request fails, for example while the relay is restarting. Everything else
  (startup, certificates) still goes to the journal.
- Caddy replaces any `X-Forwarded-For` a client sends with the real address, and the relay
  reads the last entry, so clients can't dodge the per-IP limits.

### On a server that already runs other things

A common case: the distribution's own `caddy` package serving other sites too, and another
service on port 8080.

- **Port:** if 8080 is taken (`ss -tlnp`), use another loopback port in both places:
  `BLOX_LISTEN=localhost:8090` in `/etc/blox/relay.env` and `reverse_proxy localhost:8090`.
- **Caddyfile:** don't replace it. Append the site block, and put the global `{ log … }` block
  at the very top (Caddy takes global options only there; it then applies to every site).
  Check the new file before installing it; a reload keeps the other sites up:
  ```sh
  caddy validate --adapter caddyfile --config /tmp/Caddyfile.new
  install -m 0644 /tmp/Caddyfile.new /etc/caddy/Caddyfile && systemctl reload caddy
  ```
- **Memory:** with 1 GB, cap queued messages at 128 MiB and the unit at 320 MB:
  ```sh
  sed -i 's/^#BLOX_GLOBAL_MAX_BYTES=.*/BLOX_GLOBAL_MAX_BYTES=134217728/' /etc/blox/relay.env
  mkdir -p /etc/systemd/system/blox-relay.service.d
  printf '[Service]\nMemoryMax=320M\n' > /etc/systemd/system/blox-relay.service.d/memory.conf
  systemctl daemon-reload && systemctl restart blox-relay
  ```
- **Logs:** the journald drop-in (section 5) applies to the whole host.

## 5. Logs and rotation

Both services write to the journal:

```sh
journalctl -u blox-relay -f              # the relay
journalctl -u caddy -f                   # Caddy: startup, certificates
journalctl -u blox-relay --since today
```

Rotation is the journal's. Install the limits (the whole journal: 500 MB at most, 1 GB always
free, 14 days):

```sh
install -d /etc/systemd/journald.conf.d
install -m 0644 /tmp/journald-blox.conf /etc/systemd/journald.conf.d/blox.conf
systemctl restart systemd-journald
journalctl --disk-usage
```

**More detail for a while:** set `BLOX_LOG=debug` in `/etc/blox/relay.env` and restart. Each
request then logs one line, `method=POST route="/v1/inbox/{id}" status=202 ms=0`, with the
route template, never the inbox id. Set it back to `info` afterwards; a busy relay writes a
lot at debug.

<details>
<summary>Log files with logrotate instead of the journal</summary>

For the relay, add to `/etc/systemd/system/blox-relay.service` under `[Service]`:

```ini
StandardOutput=append:/var/log/blox/relay.log
StandardError=inherit
```

then `install -d -m 0750 /var/log/blox && systemctl daemon-reload && systemctl restart blox-relay`,
and rotate with `/etc/logrotate.d/blox-relay` (`copytruncate`, because the relay keeps the
file open):

```
/var/log/blox/relay.log {
    daily
    rotate 14
    maxsize 50M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

For Caddy's own log, change `output stderr` in the Caddyfile's global block to Caddy's
built-in rotation:

```
output file /var/log/caddy/caddy.log {
    roll_size 50MiB
    roll_keep 10
    roll_keep_for 336h
}
```

</details>

## 6. Check it

From anywhere:

```sh
R=https://relay.example.com
curl -s $R/health                                    # {"ok":true}
curl -s $R/v1/info                                   # version, limits, relay time
curl -si -X OPTIONS $R/v1/inbox/x -H 'Origin: https://example.com' \
    -H 'Access-Control-Request-Method: POST' | grep -i access-control-allow-origin   # *
```

End to end without a phone (local), as in [RUN.md](RUN.md) "Without a phone" but through the
public relay: anvil and the mock keystore run locally, the messages go through the server.

```sh
scripts/local-services.sh            # anvil, a local relay (unused here) and the mock keystore
cargo run -p blox-client --example send -- --relay https://relay.example.com --print-uri \
    --chain 31337 --to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1000000000000000
# give the printed BLOX:… line to the mock keystore:
echo 'BLOX:…' > target/local/keystore.in
```

The example prints `Connected as 0xf39F…` and a transaction hash. Then
`--message hello` and `--disconnect` with the same `--relay`.

With the phone: the app, the SDK and the example requester all use `https://relay.example.com`
by default. Connect from the web demo (below) or the example requester without `--relay` and
`--print-uri`, and scan the QR code.

### The demo site

`sdk/js/demo` builds with Deno (no npm) to two static files that work under any path; `relay.example.com/demo/` serves
them from the relay's own site. Build (local) and copy:

```sh
(cd sdk/js && deno task demo)          # demo/dist: index.html and demo.js
scp -r sdk/js/demo/dist "$HOST":/tmp/blox-demo
```

On the server:

```sh
rm -rf /var/www/blox-demo && cp -r /tmp/blox-demo /var/www/blox-demo && chmod -R a+rX /var/www/blox-demo
```

and in the Caddyfile's site block, the relay goes under `handle` next to the demo:

```
relay.example.com {
	redir /demo /demo/
	handle_path /demo/* {
		root * /var/www/blox-demo
		file_server
	}
	handle {
		reverse_proxy localhost:8080 {
			flush_interval -1
		}
	}
}
```

## 7. Upgrade and roll back

Build (step 2), copy the binary, then on the server:

```sh
cp /usr/local/bin/blox-relay /usr/local/bin/blox-relay.prev
install -m 0755 /tmp/blox-relay /usr/local/bin/blox-relay
systemctl restart blox-relay
journalctl -u blox-relay -n 5 --no-pager && curl -s http://localhost:8080/health   # or your port
```

A restart takes about a second, and clients reconnect. Messages that were queued (5 minutes
at most), tickets and revocations are lost: a site sees its request time out and can send it
again; why losing revocations is safe is in BLOX.md §5.5.

Roll back:

```sh
install -m 0755 /usr/local/bin/blox-relay.prev /usr/local/bin/blox-relay && systemctl restart blox-relay
```

Caddy updates come with `apt upgrade`. After editing the Caddyfile: `caddy validate`, then
`systemctl reload caddy` (no downtime).

## 8. Operating it

- **Monitoring:** check `GET /health` from outside every minute or so (any uptime monitor).
  `GET /v1/info` returns the relay's time; if it drifts from real time, fix NTP (section 1).
- **Limits** (BLOX.md §8.4) are in `relay.env`, published at `/v1/info`. The defaults hold
  512 MB of queued messages at most; `MemoryMax=1G` in the unit leaves room above that. On a
  smaller server, lower both (section 4).
- **Restarts** are safe at any time (section 7).
- **Nothing to back up.** The relay has no data. Keep `relay.env` and the Caddyfile in this
  repository (or your own config management).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `502` from Caddy | The relay isn't running: `systemctl status blox-relay`, `journalctl -u blox-relay`. |
| `invalid value … for '--trust-proxy'` in the journal | An old relay build: those only accepted `true`/`false`. Use `BLOX_TRUST_PROXY=true`, or upgrade. |
| Everyone gets `429`, or readers are refused | `BLOX_TRUST_PROXY` isn't set, so every client looks like `localhost` and shares one set of per-IP limits. |
| No certificate, TLS errors | DNS doesn't point at the server yet, or port 80/443 is closed: `journalctl -u caddy`. |
| Requests rejected as expired, or tokens as not yet valid | The server clock is off: `timedatectl`. |
| Phones or sites see messages only after a delay | Something buffers the event stream: keep `flush_interval -1`, and nothing else (a CDN or another proxy) in between should buffer `text/event-stream`. |

## Docker instead of systemd

`deploy/Dockerfile` builds a distroless image (pin the base images by digest for production):

```sh
docker build -f deploy/Dockerfile -t blox-relay .
docker run -d --name blox-relay --restart unless-stopped \
    -p localhost:8080:8080 -e BLOX_TRUST_PROXY=1 blox-relay
docker logs -f blox-relay
```

Caddy is the same as in section 4. For log rotation with Docker, set the `json-file` driver's
`max-size`/`max-file` in `/etc/docker/daemon.json`, or use `--log-driver journald`.
