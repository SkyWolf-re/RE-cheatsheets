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
