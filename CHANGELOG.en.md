# Changelog

<p align="center">
  <a href="CHANGELOG.md">Русский</a> · <b>English</b>
</p>

Newest versions on top. The version number lives in `VERSION` and is shown in
the menu header.

**Each section below is also the release notes.** When publishing a release on
GitHub, copy the section for that version as it is — nothing needs rewriting.
The Russian version in [CHANGELOG.md](CHANGELOG.md) is the primary one.

---

## 3.6

**Backups go to Telegram.**

A copy sitting on the same disk that will one day die is not a copy. Shape now
uploads node state as a file to Telegram once a week — to the same place the
reports arrive, or to a separate topic.

### Added

* Weekly backup upload: `telegram set --backup on --backup-day 1`. The weekday
  is configurable; the time is the same as the daily digest.
* A separate topic for backups: `--backup-thread`. Empty means the copy goes
  wherever ordinary messages go.
* `shaperctl.py telegram backup` — send a copy right now.
* Items [4]–[7] on the **Service → 💾 Backup and restore** screen.
* File upload via `sendDocument` with `multipart/form-data` assembled on the
  standard library — works both directly and through the SOCKS5 proxy that
  Russian nodes rely on.
* 43 new checks in `tests/export_tests.py`, 128 in the suite overall.

### What is not in the copy, and never will be

**The bot token does not go into a copy uploaded to Telegram under any
setting.** The bot posts into the very topic it uploads the file to: anyone in
that topic — now or added six months later — would gain control of the bot and
its whole history along with the token.

The check does not rest on a flag alone: right before sending, the payload is
compared against the configured secrets once more, and a match cancels the
upload entirely. That is insurance against the code being changed badly some
day — it should fail before the token reaches the chat, not after.

A copy with secrets is still possible, but only as a file on disk:
`export --with-secrets`, for moving a node.

### Worth remembering

The file holds client IP addresses, and names and telegram_id values when
owners are filled in. That is personal data, and in Telegram it stays forever,
visible to everyone in the topic. The menu warns about this when you enable it
and asks for confirmation.

### Behaviour on failure

* No connectivity — the next attempt is in an hour, not every ten seconds.
* A missed day is not caught up: the state sent is the current one, not what
  it was on Monday.
* A malformed weekday, a corrupted state file and an unreachable API do not
  bring the watchdog down — each is covered by its own test.

### Upgrading

The setting is off by default and shaper behaviour is unchanged. To turn it
on:

```bash
shaperctl.py telegram set --backup on --backup-day 1
shaperctl.py telegram backup        # check it straight away
```

## 3.5

**Node state backup.**

Node state — settings, whitelist, personal speeds, active limits, address
owners and daily history — can now be exported to a single file and restored
from it.

The reason is plain: going from twenty-eight nodes to a hundred leaves no
room for repeating setup by hand, and a backup sitting on a dead disk is not
a backup.

### Added

* `shaperctl.py export --out FILE` — export state into a single JSON.
* `shaperctl.py import FILE` — restore, with `--dry-run`, `--only`
  and `--replace`.
* A **Service → 💾 Backup and restore** screen: save, restore with a
  mandatory parse-and-confirm step, and a separate file check.
* A `tests/export_tests.py` suite — 85 checks, including the round trip
  "export → wipe → restore → state matches".

### How it is protected

* **Secrets are not exported by default.** The bot token and proxy password
  stay out of the file; `--with-secrets` is there for cloning a node. The
  file is created with mode `600`, and the mode is set before writing rather
  than after.
* **The receiving node's token is never wiped.** Restoring from a
  secret-free backup leaves the token configured here in place — otherwise
  notifications would go silent without a word.
* **The file is not trusted.** It may come from another node or have been
  edited by hand, so every value goes through the same checks as ordinary
  input: addresses, speeds, ports, field types in the `guard` and `telegram`
  sections. Anything unusable is dropped with a note instead of crashing the
  command halfway through writing.
* **Writes go through the normal functions only** — `save_config`,
  `penalties_update`, `owners_update`. An import writing to files directly
  would bypass the locks that protect them from concurrent edits by the
  watchdog.
* The format carries a version: a file from a newer Shape is rejected with a
  clear message rather than parsed halfway.

### Fixed

* The CI secret scanner matched the sample tokens in the test suites and
  would have failed the build. The values are unchanged, but the sources no
  longer contain a contiguous literal that looks like a real token.

### Upgrading

Nothing to configure; shaper behaviour is unchanged. Right after upgrading it
is worth taking a copy:

```bash
shaperctl.py export --out /root/shape-$(hostname -s).json
```

and copying the file off the server.

## 3.4

**Holding time is back, and the whitelist became visible.**

- **The "holding" column returned.** In 3.3 it became a mark on the left, and
  the important part went with it: how many minutes in a row an address has
  been loading the channel. The mark only says "over thirty seconds", while
  the difference between two minutes and forty-four is the difference between
  a burst and a torrent.
- **Whitelisted addresses now show up in the monitor, the statistics and the
  metrics.** The whitelist check used to sit in eBPF **before** accounting, so
  such an address vanished everywhere: there was no way at all to tell how much
  of the channel it was eating. And it can eat any amount — the limit does not
  apply to it. Now everyone is counted and not everyone is limited.
- A **✓** mark tags those addresses in the monitor so they are not mistaken for
  ordinary ones.
- The "1-min avg" header was shortened to "avg": next to "upload" it did not
  fit and ran into the neighbouring column.

The change touches the eBPF program, which is rebuilt automatically on update.
Settings, penalties and the whitelist are untouched.

## 3.3

**The monitor got a new look.** Rendering only — not a single extra call into
the kernel, apart from reading the penalty list once every five seconds.

- **Bars are smooth now.** A block used to be either whole or absent: at twelve
  characters wide that gave twelve levels in total, and the difference between
  7.3 and 7.4 Mbit/s was invisible. Eighth-width blocks give 96 levels at the
  same width.
- **Colour follows the share of the limit, not the "holding" flag.** Grey up to
  20%, green to half, yellow to 80%, red above. Previously colour appeared only
  when an address had been holding load for over thirty seconds, so on a quiet
  node the screen was monochrome and the eye had nothing to catch.
- **Upload has its own colour scale.** Mobile carriers give a narrow uplink, so
  noticeable upload is the first sign of seeding. An address that downloads
  little but uploads a lot is now visible at once.
- **The "holding" column became a mark on the left.** In a quiet hour it was
  nothing but dashes and wasted nine characters. The freed space now shows the
  share of the limit in percent, which is what the bar length means anyway.
- **A ⊘ mark on limited addresses.** The monitor used to give no hint that an
  address was already under a penalty — you had to open another screen.
- **A channel sparkline for the last minute** in the header: you can see
  whether load is rising or falling.
- A "showing N of M" footer instead of "… N more active", separators and
  aligned columns.

Updating is safe: settings, penalties and the whitelist are untouched.

## 3.2

**Metrics no longer require the API.**

Metric text assembly moved from `api/server.py` into `shaperctl.py`, next to
the rest of the logic. This fixes a violation of the project's own rule: logic
lives in the shared layer, the API is a thin shell over it.

- **`shaperctl.py metrics`** prints the same metrics to stdout, and with
  `--out` writes a file for the node_exporter textfile collector — through a
  temporary file and a rename, so the exporter never reads half a file.
- **A monitoring wizard** in the menu: Service → 📈 Monitoring. It finds the
  node_exporter directory, installs a systemd timer, shows a ready
  `scrape_configs` snippet and can switch everything back off.
- The timer refreshes the file once a minute. No open ports, no tokens and no
  API are needed for monitoring any more.
- **New metric `shape_metrics_complete`:** zero means the BPF maps could not be
  read and the numbers are incomplete. "No traffic" and "we could not look" are
  different things, and monitoring now tells them apart. The dashboard got a
  panel for it.
- On top of the shared set the API adds two of its own metrics: `shape_api_up`
  and `shape_api_uptime_seconds`.
- Channel speed is derived from the previous sample, and that sample lives in a
  file rather than in process memory — so it works for one-off CLI runs and for
  any mix of sources.
- State and configuration directories can be overridden with `SHAPE_VAR_DIR`
  and `SHAPE_ETC_DIR`, which lets the tests run the real CLI without touching
  the system.
- The test suite now checks that the metric set from the CLI matches the one
  from the API, apart from the two API-only metrics. CI runs the no-API path as
  a separate step.

In the menu, "Monitoring" is item nine under Service; the API moved to ten.

Updating is safe: settings, penalties and the whitelist are untouched.

## 3.1

**Monitoring, history and groundwork for user names.**

- **Prometheus metrics** at `/metrics` — with a `node` label on every metric so
  graphs are labelled by node name rather than by address and port. A ready
  Grafana dashboard for the whole fleet and a sample `scrape_configs` live in
  `grafana/`. By default metrics require a read token; on a private network
  they can be opened with the `metrics_public` flag.
- **History by day.** Before the counters reset at midnight, a row is written
  to `/var/lib/shape/history.jsonl`: date, volumes, address count, how many
  limits were issued and the five heaviest addresses. A hundred bytes a day.
  Menu → Statistics → History, `shaperctl.py history`, `GET /api/v1/history`.
- **Personal speeds.** A permanent speed for one address — above or below the
  shared limit. Built on the existing penalty mechanism; no kernel changes were
  needed. Auto-limiting leaves such addresses alone and they are not shown in
  the limited list.
- **An owner map for addresses.** `/var/lib/shape/owners.json`: name,
  telegram_id, panel identifier, shared-address flag. The label is attached to
  a limit at the moment it is issued and reaches the notification — with a
  `tg://user?id=…` link that works even without a username. Filled in by hand or
  in bulk through `PUT /api/v1/owners`. A Remnawave resolver will write here
  once it exists; Shape itself never goes looking for this data.
- **Graceful API token rotation.** The previous pair is accepted for another
  day, so the central system can be updated at a comfortable pace without 401s
  on half the fleet.
- **Tests moved into the repository** (`tests/`) and run in GitHub Actions on
  every push: syntax, ShellCheck, ruff, bandit, an eBPF build with the real
  clang, the program run against synthetic packets, 208 API checks, version
  consistency and interface strings, and a search for accidentally committed
  secrets.

Updating is safe: settings, penalties and the whitelist are untouched.

## 3.0

**Node API — an optional interface for external systems.**

```
central system  →  Shape API  →  Shape  →  BPF
```

- A local HTTP service `shape-api`, versioned from the start at `/api/v1/`.
  It listens on `127.0.0.1:8765` by default, exposes nothing outward and does
  not touch the firewall. For a private network the address and the allowed
  networks are set in the menu.
- **The API has no limiting logic of its own.** It calls the same
  `shaperctl.py` functions the menu does, so behaviour cannot drift apart.
- Endpoints: health, status, node, limits (list, one address, create, remove,
  temporary), stats, events, config, bpf/status. The OpenAPI schema is served
  at `/api/v1/openapi.json`, the documentation page at `/api/v1/docs`.
- Two tokens: read-only, and read plus write. Generated on the node itself at
  first start, stored in `/etc/shaper/api.json` with mode 600, absent from the
  repository. Reissued from the menu.
- Rate limiting separately for reads, writes and failed authorisations. Limits
  on body size, on the number of concurrent handlers and on process memory.
- Structured errors with a code and a `request_id`; no tracebacks reach the
  client. The same `request_id` is written to the node's log.
- **Shape stays self-sufficient.** The API unit is tied to the shaper unit by
  nothing but `After=`: a crash, a stop or a removal of the API does not affect
  the shaper. Verified by a dedicated test suite.
- Installation: `install.sh --with-api`. Without the flag exactly the previous
  Shape is installed; API files are placed but the service is not enabled — it
  can be enabled later from the menu. Removing only the API:
  `install.sh --uninstall-api`.
- The same port on every node creates no conflicts: a node knows nothing about
  other nodes, there is no shared state and no database.

Shared between Shape and the API:

- Penalties are now written under a file lock: the watchdog, the CLI and the
  API all edit them, and without a lock one write could erase another.
- An event log appeared at `/var/lib/shape/events.jsonl` — limits, releases,
  watchdog triggers, engine start and stop, API actions. Every part of Shape
  writes there and reads from there.

Documentation and small things:

- An English README — [README.en.md](README.en.md), with a language switcher in
  the header of both files. The Russian version stays primary.
- A link to support the project: in the README and as one line in the footer of
  the main menu screen. It is absent from the working screens — they are dense
  enough already.

## 2.8

**Security audit: a pass over the whole project, with fixes.**

Fixes you can see in operation:

- **Editing any auto-limit setting wiped the entire Telegram section.** Token,
  chat, topic, proxy and digest time silently returned to empty values —
  saving the config rebuilt the file and simply left that section out. The
  config is now written by merging with what is already on disk, so a section
  cannot be lost even by accident.
- **Daily counters were not kept while auto-limiting was off** — the Telegram
  digest always arrived empty on such nodes. Traffic accounting is now separate
  from issuing penalties.
- **A non-first IPv4 fragment was parsed as if it carried a TCP header.**
  Payload bytes were read as port numbers and sometimes matched a rule by
  accident. Fragments are now recognised explicitly.
- **An IPv6 packet with any extension header bypassed the shaper:** the
  protocol in it is neither TCP nor UDP, and the code gave up at the first
  step. A bounded walk over the header chain was added.

Security:

- External commands (`bpftool`) run without a shell — the command line used to
  be assembled and handed to `/bin/sh` as root.
- Every value a human types is validated: IP, ports, speed, token, chat_id,
  topic, proxy, digest time, SSH address and user. Junk in a field previously
  ended up either in a Python traceback or in files that are later executed as
  root.
- Writes to `shaper.conf` are escaped: the file is read through `source` as
  root, and a quote in a value would have meant command execution at every
  start.
- The SSH tunnel wizard shows the server host key fingerprint and asks for
  confirmation, then works with its own `known_hosts`. Previously the first
  connection was taken on trust, and the bot token travels through that tunnel.
- The token is scrubbed from error texts that reach journalctl.
- The node label is escaped: a `<` in it used to break message delivery.
- `/etc/shaper` is 750 and `config.json` is 600, set at install time.
- The watchdog unit gained systemd restrictions (ProtectSystem, ProtectHome,
  PrivateTmp). They were deliberately not added to the engine: it mounts
  `/sys/fs/bpf`, and its own mount namespace would make the maps invisible.
- Removing Shape also removes the SSH tunnel unit.

Updating is safe: settings, penalties and the whitelist are untouched.

## 2.7

**The Telegram digest gets fixed and gains a schedule.**

- **Fixed: the daily digest was never sent at all.** The digest text was
  assembled, but the watchdog loop had no midnight rollover, so the function
  was never called. Days are now closed explicitly.
- **Digest time is configurable** — menu → Telegram → `[9]`, `09:00` node local
  time by default. Midnight used to be implied.
- **A digest can be sent by hand** — menu → Telegram → `[10]`. It reports the
  current, not yet finished day. Works with notifications off too, as long as a
  token and a chat are set.
- The snapshot of the finished day is stashed in `/etc/shaper/digest.json` and
  waits for the appointed hour. With no connectivity it retries every fifteen
  minutes for a day, then the digest is dropped: the day-before-yesterday's
  numbers are of no use to anyone.
- Items in the Telegram screen were renumbered: the test message is now `[11]`,
  the SSH tunnel `[12]`.

Updating is safe: settings, penalties and the whitelist are untouched.

## 2.6

- **The SSH tunnel wizard** — menu → Telegram → SSH tunnel. It asks for the
  address of a foreign node, the port, the user and the local SOCKS port; then
  generates an ed25519 key, installs `autossh`, writes a systemd unit with
  automatic restart, brings the tunnel up and verifies it with a real request
  to the Bot API.
- On success the proxy is written into the notification settings automatically.
- Removal in a single item, with the proxy cleared.

## 2.5

- **Telegram notifications.** Off by default.
- Events: an address gets limited — a message with the reason and the duration.
- Daily digest: traffic, address count, the five heaviest.
- Forum group topics through `message_thread_id`.
- An editable node label: all nodes write into one topic and it is clear which
  one fired.
- SOCKS5 and HTTP proxies implemented on the standard library, no `PySocks`
  needed. MTProto `t.me/proxy` links are rejected with an explanation.

## 2.4

- Wording fixed everywhere: the limit applies to an **IP address**, not to a
  user. Several people can sit behind one address.
- The limited list shows the time an address was limited.
- A banner and a screenshot in the README — a link to the project now unfolds
  nicely in Telegram.

## 2.3

- **An hourly volume threshold**, and it is the main rule: someone watching
  video for ten hours straight is not punished, while a download hits the limit
  in forty minutes.
- A ready **"phone-only node"** preset: 3 GB per hour, 25 GB per day as a
  backstop, a four-hour penalty.
- The daily threshold stayed as a fallback.

## 2.2

- Optimised for weak hardware: one core and 2 GB of RAM.
- LRU maps reduced from 65536 to 8192 entries — the watchdog cycle got about
  ten times cheaper.
- The menu stopped spawning a dozen `python3` processes per screen redraw.

## 2.1

- The logo in the main menu, plus the state of the shaper, autostart, speed and
  ports on the first screen.
- Autostart guaranteed at install time.

## 2.0

- **Auto-limiting of heavy addresses** on a combination of signals: two-way
  load, average upload packet size, hours of activity, volumes per hour and per
  day. Each signal scores points; a penalty is issued once the threshold is
  reached.
- A real-time per-address speed monitor.

## 1.x

- The first standalone version: ports, speed in Mbit/s per address, a
  whitelist, a Russian and English menu, systemd, updates from the repository.
