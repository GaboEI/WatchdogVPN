# Provider Collaboration

WatchdogVPN is provider-agnostic. The project can import compatible
subscription/profile data from external VPN or proxy providers, but it does not
depend on, bundle, certify or endorse any specific provider.

This page is for providers or operators who want their subscription output to
work cleanly with WatchdogVPN.

## Accepted Input Families

WatchdogVPN can work with these profile/subscription families as they are added
and validated in the v2 line:

| Format | Notes |
| --- | --- |
| Protocol URIs | `vless://`, `trojan://`, `hy2://`, `tuic://`, `ss://`, `vmess://` and related supported URI forms |
| V2Ray/Base64 subscriptions | Newline-separated protocol URI feeds after Base64 decode |
| sing-box JSON | Profile/config data that preserves sing-box fields needed by the protocol |
| Clash/Stash YAML | Proxy lists and rule-provider style data where safely mappable |
| WireGuard/OpenVPN configs | Compatibility imports validated against a fail-closed directive whitelist; see `docs/security.md#openvpn-and-openvpncloak-profile-safety` |

Unsupported or malformed data should fail with clear errors. HTML login pages,
captive portal bodies, empty subscriptions and loopback endpoints are not valid
provider output.

OpenVPN and OpenVPN+Cloak profiles are parsed with a fail-closed safety model.
Dangerous executable directives, external file references and non-global
endpoints are rejected before the profile is stored. See the security document
for the exact restrictions and process-isolation guarantees.

## Resilient vs Compatibility Profiles

Providers should not flatten all protocols into the same marketing category.
WatchdogVPN separates resilient profile families from compatibility profiles:

| Category | Examples |
| --- | --- |
| Resilient / anti-DPI oriented | VLESS+Reality, Trojan TLS/uTLS, Hysteria2, AmneziaWG, OpenVPN+Cloak/OverCloud |
| Compatibility | plain WireGuard, VMess, standard Shadowsocks, SOCKS, HTTP, normal OpenVPN |
| Conditional | TUIC or Shadowsocks only when the concrete configuration is validated for restrictive networks |

If a profile needs specific anti-DPI fields, providers should preserve those
fields instead of reducing the profile to a minimal generic template.

## Provider Metadata

Useful metadata can include:

- provider display name;
- node name;
- country/region;
- protocol;
- traffic usage/limit when available;
- expiration date when available;
- update interval;
- provider website or support URL.

Metadata must not be used to silently weaken user policy. For example,
provider-supplied routing rules should be visible, reviewable and disableable
by the user.

## Routing Rules

Provider-provided rules may be useful, but WatchdogVPN treats traffic policy as
user-owned. A provider can suggest rules; the user must remain able to inspect,
disable and override them.

Recommended behavior:

- keep rules grouped by source;
- label provider-owned rule groups clearly;
- avoid hidden global defaults;
- avoid rules that bypass user privacy expectations;
- document whether rules are intended for direct, proxy, block or auto-selected
  routing.

## Submission Path

Open a GitHub issue or pull request with:

- provider name;
- sample sanitized subscription output;
- supported protocol families;
- expected parser behavior;
- whether the sample contains routing rules;
- any required client version or protocol notes;
- validation notes if available.

Do not include private keys, credentials, customer tokens, account identifiers
or live paid subscription URLs in public issues.

## What WatchdogVPN Will Not Do

- It will not endorse a provider by default.
- It will not hide provider behavior from the user.
- It will not accept provider data that silently rewrites local policy.
- It will not claim censorship resistance for a compatibility profile.
- It will not require users to use any specific provider.

## Maintainer Review Checklist

Before provider compatibility is documented as supported:

- parser accepts the sample without losing important protocol fields;
- malformed input fails with a controlled error;
- credentials/secrets are not logged;
- route/DNS behavior is explicit;
- profile category is correctly marked resilient or compatibility;
- tests cover the provider format or representative fixtures.
