This folder collects translation tables that map:

Raw hex bytes → Assembly mnemonics → C-like equivalents / behavior for different Instruction Set Architectures (ISAs)

## Notation Legend

To keep tables concise, the following placeholders are used:

- `xx` → one-byte immediate or displacement value (offsets, locals, short jumps).
- `yy yy yy yy` → multi-byte immediate (e.g., 32-bit constant literal).
- `imm8`, `imm32` → immediate value of given size.
- `disp8`, `disp32` → displacement relative to base/frame pointer (`ebp`, `rbp`).
- `local` → local variable (e.g., `[ebp-4]`).
- `arg` → function argument (e.g., `[ebp+8]`).
- `const` → literal constant value.
- `ptr` → pointer (global/static memory reference).
- `arr[index]` → array access pattern (using scaled index).
- `immN` → immediate value with N bits as encoded by the instruction (e.g., imm12 in add/sub).
- `off` → unsigned, scaled offset used by load/store (e.g., ldr x0, [sp, #off]; scaled by access size).
- `disp` → signed, unscaled displacement used by ldur/stur (e.g., stur x0, [sp, #disp]).
- `local[k]` → stack slot at (sp, #k) (stack grows down, 16-byte aligned).  
    Example: stur x0, [sp, #-16] → local[-16] = x0.    
- `argN` → function argument N in register (arg0=x0 … arg7=x7 under AAPCS64).  
    Return value: ret is x0 (or w0/s0/d0 for 32-bit/float/double).  
- `ptr(sym)` → pointer to global/static symbol via PC-relative materialization (adrp xN, sym@PAGE + add xN, xN, sym@PAGEOFF) or literal pool (ldr xN, =sym).
- `arr[index]` → array access using scaled index form [xBase, wIndex, uxtw #scale] where scale = log2(elem_size).  
    Example: ldr w0, [x1, w2, uxtw #2] → w0 = arr[w2].  
- `alias` → instruction is an alias of a canonical op (e.g., mov x0, x1 ≡ orr x0, xzr, x1; cmp a,b ≡ subs xzr, a, b).
- `wN/xN note` → writing wN zero-extends into xN (32→64). C-like side reflects that.
