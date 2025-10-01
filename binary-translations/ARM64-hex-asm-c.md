A list of common ARM64 (AArch64) instructions

## 1. Function Prologue & Epilogue

| *Hex*         | *Assembly*                                 | *C Equivalent*     | *Notes*                                                  |
| ------------- | ------------------------------------------ | ------------------ | -------------------------------------------------------- |
| `FD 7B BF A9` | `stp x29, x30, [sp, #-16]!`                | —                  | Push FP/LR pair; make new stack frame (16-byte aligned). |
| `FD 03 00 91` | `mov x29, sp` *(alias: `add x29, sp, #0`)* | —                  | Set frame pointer.                                       |
| `FF xx 00 D1` | `sub sp, sp, #imm`                         | `uint8_t local[n]` | Reserve local stack space (imm multiple of 16).          |
| `FF xx 00 91` | `add sp, sp, #imm`                         | —                  | Free local stack space.                                  |
| `FD 7B C1 A8` | `ldp x29, x30, [sp], #16`                  | —                  | Pop FP/LR pair; restore caller frame.                    |
| `C0 03 5F D6` | `ret`                                      | `return;`          | Return to address in `x30` (LR).                         |

---
## 2. Data Movement

| *Hex*         | *Assembly*                              | *C Equivalent*        | *Notes*                                                        |
| ------------- | --------------------------------------- | --------------------- | -------------------------------------------------------------- |
| `E0 03 00 AA` | `mov x0, x0` *(self move; template)*    | —                     | `mov` is an alias (e.g., `orr x0, xzr, xN`).                   |
| `20 00 80 D2` | `mov x0, #1` *(alias of `movz`)*        | `x0 = 1;`             | Small constants via `movz/movn/movk`.                          |
| `E0 03 1F AA` | `mov x0, xzr`                           | `x0 = 0;`             | Zero register write yields zero.                               |
| `E0 43 00 B9` | `ldr w0, [sp, #0x10]` *(example)*       | `w0 = *(uint32_t*)p;` | Scaled/offset addressing; exact bytes vary by offsets/regs.    |
| `E0 03 00 F9` | `str x0, [sp]` *(example)*              | `*(uint64_t*)p = x0;` | 64-bit store.                                                  |
| `00 00 00 58` | `ldr x0, =sym` *(literal pool; pseudo)* | `x0 = &sym;`          | Often materialized via `adrp` + `add` pair.                    |
| `00 00 00 90` | `adrp x0, sym@PAGE` *(template)*        | `x0 = page(sym);`     | Page-relative address (paired with `add x0, x0, sym@PAGEOFF`). |
| `00 00 00 91` | `add x0, x0, sym@PAGEOFF` *(template)*  | `x0 = &sym;`          | Complete PC-relative address calc.                             |
| `20 00 00 0B` | `add w0, w1, w0` *(example)*            | `w0 += w1;`           | 32-bit variants use `wN`.                                      |

---
## 3. Arithmetic & Logic

| *Hex*         | *Assembly*                          | *C Equivalent*   | *Notes*                                       |
| ------------- | ----------------------------------- | ---------------- | --------------------------------------------- |
| `00 00 00 8B` | `add x0, x0, x0` *(example)*        | `x0 += x0;`      | Register add.                                 |
| `00 00 00 CB` | `sub x0, x0, x0` *(example)*        | `x0 -= x0;`      | Register sub.                                 |
| `00 00 80 D2` | `mov x0, #0` *(movz)*               | `x0 = 0;`        | Zero constant.                                |
| `00 04 00 8B` | `add x0, x0, x1, lsl #1`            | `x0 += (x1<<1);` | Add shifted register.                         |
| `20 7C 00 9B` | `mul x0, x1, x0` *(example)*        | `x0 *= x1;`      | 64-bit multiply.                              |
| `20 00 00 1A` | `cmp x1, x0` *(alias: `subs xzr,…`) | `if (x1 - x0)`   | `cmp a,b` ≡ `subs xzr, a, b` sets flags.      |
| `00 00 00 D3` | `lsl x0, x0, #0` *(template)*       | `x0 <<= k;`      | Shift/extend family (`lsl/lsr/asr/ror`).      |
| `00 00 00 AA` | `mov x0, x0` *(alias of `orr`)*     | —                | Logical ops: `and/orr/eor/bic` for bit masks. |
| `00 00 00 4A` | `eor w0, w0, w0` *(example)*        | `w0 ^= w0;`      | 32-bit XOR zeroing.                           |
| `00 00 00 2A` | `orr w0, wzr, w0` *(example)*       | `w0 = w0;`       | `mov` alias illustration.                     |

---
## 4. Control Flow (Jumps & Calls)

| *Hex*         | *Assembly*            | *C Equivalent*     | *Notes*                                                      |
| ------------- | --------------------- | ------------------ | ------------------------------------------------------------ |
| `xx xx xx 94` | `bl <rel>`            | `func();`          | PC-relative call; low 26-bit signed offset → *word* units.   |
| `xx xx xx D6` | `blr xN`              | `fp();`            | Branch & link to register.                                   |
| `xx xx xx 14` | `b <rel>`             | `goto;`            | Unconditional branch.                                        |
| `?? ?? ?? 54` | `b.<cond> <rel>`      | `if (…) goto;`     | Conditional branch (`b.eq`, `b.ne`, `b.lt`, `b.gt`, …).      |
| `xx 00 00 B4` | `cbz xN, <rel>`       | `if (xN==0)`       | Compare-and-branch on zero (32/64-bit: `cbz/cbnz`, `wN/xN`). |
| `xx 00 00 36` | `tbz xN, #bit, <rel>` | `if(!(xN>>bit)&1)` | Test bit and branch (`tbz`/`tbnz`).                          |

---
## 5. Memory Addressing

| *Hex*         | *Assembly*                               | *C Equivalent*                      | *Notes*                                    |
|---------------|------------------------------------------|-------------------------------------|--------------------------------------------|
| `xx xx 40 F9` | `ldr Xt, [Rn, #imm12]`                   | `Xt = *(uint64_t*)(Rn + off)`       | Unsigned offset; scales by access size.    |
| `xx xx 00 F9` | `str Xt, [Rn, #imm12]`                   | `*(uint64_t*)(Rn + off) = Xt`       | Store with immediate offset.               |
| `xx xx xx B8` | `ldr Wt, [Xbase, Widx, uxtw #scale]`     | `Wt = base[index];`                 | Register offset with scale (array access). |
| `xx xx xx F8` | `stur Xt, [Rn, #disp9]`                  | `*(Rn + disp) = Xt`                 | Unscaled (signed) offsets via `stur/ldur`. |
| `xx 00 00 58` | `ldr Xt, =imm64`                         | `Xt = imm;`                         | PC-relative literal load from nearby pool. |

---
## 6. System & Special

| *Hex*         | *Assembly* | *C Equivalent* | *Notes*                                        |
| ------------- | ---------- | -------------- | ---------------------------------------------- |
| `1F 20 03 D5` | `nop`      | —              | No-op (official encoding).                     |
| `XX 00 00 D4` | `svc x0..` | `syscall(...)` | Supervisor call (Linux: `x8=nr`, `x0..` args). |
| `00 00 20 D4` | `brk #0`   | —              | Breakpoint trap.                               |
| `DF 3F 03 D5` | `isb`      | —              | Instr. sync barrier (pipeline flush).          |
| `DF 3F 03 D5` | `dsb sy`   | —              | Data sync barrier.                             |

---

## Notes

* **Address materialization:** Absolute addresses typically use `adrp + add` (page + pageoff).
* **Condition codes:** `eq, ne, lt, le, gt, ge, hi, lo, cs, cc`, etc.—set by preceding `cmp/subs/cm n …`.

---

**Sources:**
ARM® Architecture Reference Manual for A-profile (A64) — instruction set & encodings
AAPCS64 (Procedure Call Standard for the ARM 64-bit Architecture) — calling convention & ABI notes
