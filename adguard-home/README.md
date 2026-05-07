# AdGuard Home Integration

AdGuard Home is optional.

Without AdGuard Home, WatchdogVPN uses the normal system DNS path and
the TUI DNS screen remains limited.

With AdGuard Home, the product provides advanced DNS profiles, backup,
validation and rollback through `vpn_dnsctl`.

If the user enables advanced DNS during installation, WatchdogVPN:

- installs AdGuard Home with the official upstream installer when missing;
- preserves an existing `AdGuardHome.service` and configuration when present;
- creates a local-only starter configuration when no config exists;
- applies the default DNS profile with backup and rollback;
- keeps the web interface bound to `127.0.0.1:3000`.

The default generated configuration disables web authentication because the web
interface is local-only. Users can later create web credentials from AdGuard
Home if they expose the interface beyond localhost.
