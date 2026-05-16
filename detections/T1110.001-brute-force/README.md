# T1110.001 — Brute Force: Password Guessing (Detecting the Successful Logon)

## Summary

Wazuh's built-in brute-force detection (rule **60204**) flags repeated Windows
authentication failures — but it never flags the *eventual success*. An analyst
sees "multiple logon failures" and has to manually pivot to find out whether any
attempt actually worked.

This detection adds custom rule **100204**, a composite rule that fires when a
**successful** Windows logon arrives from the same source IP that just triggered
60204. It catches the actual credential compromise — the kill shot — not just
the noise of failed attempts.

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| T1110.001 | Brute Force: Password Guessing |
| T1078     | Valid Accounts (the post-compromise logon) |

## The gap in built-in coverage

Built-in rule 60204:

- Level 10, MITRE **T1110** (parent technique only — not a sub-technique)
- `if_matched_group authentication_failed`, `same_field win.eventdata.ipAddress`
- `frequency $MS_FREQ` (=8), `timeframe 240` — fires on 8+ failures from one IP

60204 is solid for surfacing the brute force itself, but it stops there. There is
no automatic escalation when the brute force *works*. That window — between
"someone is guessing passwords" and "someone is now logged in" — is exactly where
an analyst needs to be paged.

**Baseline:** 0 prior 60204 alerts in the lab, and 0 `4625` events ever logged —
the endpoint had simply never been brute-forced. Logon auditing was already set
to *Success and Failure* by default, so (unlike T1053.005) no audit-policy change
was required.

## Detection logic — rule 100204

```xml
<rule id="100204" level="14" frequency="2" timeframe="300">
  <if_group>authentication_success</if_group>
  <if_matched_sid>60204</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  <field name="win.eventdata.ipAddress" type="pcre2" negate="yes">^-$|^::1$|^127\.0\.0\.1$</field>
  <field name="win.eventdata.targetUserName" type="pcre2" negate="yes">\$$|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$|^ANONYMOUS LOGON$|^DWM-|^UMFD-</field>
  <description>Successful Windows logon for $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress) after multiple authentication failures - potential brute force success / credential compromise</description>
  <options>no_full_log</options>
  <mitre>
    <id>T1110.001</id>
    <id>T1078</id>
  </mitre>
  <group>authentication_success,attack,T1110,T1110.001,T1078,brute_force,credential_compromise,</group>
</rule>
```

How it works:

- `if_group authentication_success` — triggers on *any* successful Windows logon
- `if_matched_sid 60204` — only if the built-in brute-force correlation fired first
- `same_field win.eventdata.ipAddress` — the success must originate from the *same IP* as the brute force
- `frequency 2 / timeframe 300` — composite window
- field filters exclude service/loopback source IPs and machine/system accounts
- level 14 (high) — actionable, page-worthy

## Engineering notes — three things that weren't obvious

### 1. Anchor on the group, not a single rule

The first version anchored the rule with `if_sid 60106` ("Windows Logon Success").
It never fired. Investigation showed why: an SMB logon using NTLM doesn't stop at
60106 — it climbs a four-rule chain:

```
60106  Windows Logon Success
  └─ 92651  Successful Remote Logon (non-loopback IPv4 source)
       └─ 92652  + NTLM auth  →  "possible pass-the-hash"
            └─ 92657  + workstation name  →  "possible RDP"
```

The event's *final* matched rule is 92657. Anchoring rule 100204 with `if_sid 60106`
placed it on a sibling branch the event never traversed, so it was never
evaluated. **Fix:** every rule in that chain carries `authentication_success` in
its `<group>`, so `if_group authentication_success` anchors 100204 correctly no
matter which rule the event ends on.

### 2. Wazuh forbids `frequency="1"`

The natural design — "fire on the *first* success after a brute force" — needs
`frequency 1`. Wazuh rejects it outright (`Invalid frequency: 1. Must be higher
than 1`). The rule was rebuilt as `frequency 2`, requiring **2 or more** successful
logons. This is arguably the better detection anyway: a single success after
failures might be the legitimate user finally typing the right password; two or
more sessions from a brute-forcing IP is unambiguous compromise.

### 3. Account lockout interrupts a naive brute force

The endpoint enforces Windows 11's default account-lockout policy — **10 failed
attempts locks the account** (confirmed empirically: attempt 11 returned
`NT_STATUS_ACCOUNT_LOCKED_OUT`, and the locked account then rejected even the
*correct* password). The test was deliberately calibrated to **9 failures** —
enough to trip 60204's threshold of 8, but under the lockout limit.

This mirrors real attacker tradecraft: **password spraying** exists precisely to
stay under per-account lockout thresholds. Lockout and rule 100204 are
complementary layers — lockout slows the attacker; 100204 catches them if they
succeed anyway (by spraying, or by guessing within the threshold).

## Empirical validation

Attack simulated from the Wazuh manager (192.168.18.132, acting as attacker)
against the Windows endpoint (192.168.18.134) over SMB, targeting a throwaway
account `labtest`:

| Stage | Events generated | Wazuh rule triggered | Level |
|-------|------------------|----------------------|-------|
| 9 failed SMB logons (wrong passwords) | 9 × event 4625 | **60204** — Multiple Windows Logon Failures | 10 |
| 2 successful SMB logons (correct password) | 2 × event 4624 | **100204** — Successful logon after brute force | 14 |

Rule 100204 fired with `targetUserName: labtest`, `ipAddress: 192.168.18.132`, and
the full credential-compromise description — the brute force and the successful
logon correctly tied together by source IP.

## Limitations

- **Source-IP correlation.** `same_field` ties the failures and the success by
  source IP. An attacker who brute-forces from one host then logs in from another,
  or rotates IPs, breaks the correlation. This is an accepted trade-off — IP
  correlation is what keeps the rule precise and false-positive-free.
- **Brute-force vector.** The lab used SMB. RDP, WinRM and other network logon
  types would also trip 60204 → 100204 (the rules are logon-type-agnostic), but
  were not individually tested.
- **Multi-fire.** The composite rule fired once per successful logon (2 alerts for
  2 logons). Acceptable for a level-14 alert, but chatty — could be dampened with
  the `ignore` attribute.
- **Firewall change for testing.** The test required temporarily allowing inbound
  SMB (TCP 445) on the endpoint firewall; removed during cleanup.
- **Lockout precedence.** In production, account lockout would interrupt a naive
  high-volume brute force before 100204 ever sees a success — see Engineering
  Note 3.

## Files

| File | Purpose |
|------|---------|
| `rule.xml` | Wazuh custom rule 100204 |
| `test/setup-and-trigger.md` | Environment prep + attack reproduction steps |
| `evidence/` | Dashboard and terminal proof |

## References

- MITRE ATT&CK — [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078](https://attack.mitre.org/techniques/T1078/)
- Wazuh ruleset syntax — composite rules (`if_matched_sid`, `frequency`, `timeframe`)
