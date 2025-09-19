
A list of common x86 instructions
## 1. Function Prologue & Epilogue

| *Hex*      | *Assembly*      | *C Equivalent*     | *Notes*                                  |
| ---------- | --------------- | ------------------ | ---------------------------------------- |
| `55`       | `push ebp`      | —                  | Save old base pointer.                   |
| `8B EC`    | `mov ebp, esp`  | —                  | Setup new stack frame.                   |
| `83 EC xx` | `sub esp, imm8` | `int localVar[n];` | Allocate locals on stack.                |
| `C9`       | `leave`         | —                  | Restore frame (`mov esp, ebp; pop ebp`). |
| `C3`       | `ret`           | `return;`          | Return from function.                    |
| `5D C3`    | `pop ebp; ret`  | `return;`          | Common function epilogue.                |

--- 
## 2. Data Movement

| Hex*             | *Assembly*             | *C Equivalent* | *Notes*                      |
| ---------------- | ---------------------- | -------------- | ---------------------------- |
| `B8 xx xx xx xx` | `mov eax, imm32`       | `eax = const;` | Load constant into register. |
| `89 45 xx`       | `mov [ebp+disp8], eax` | `local = eax;` | Store eax to local.          |
| `8B 45 xx`       | `mov eax, [ebp+disp8]` | `eax = local;` | Load local into eax.         |
| `A1 xx xx xx xx` | `mov eax, [addr]`      | `eax = *ptr;`  | Load global var.             |
| `A3 xx xx xx xx` | `mov [addr], eax`      | `*ptr = eax;`  | Store eax to global.         |
| `8D 45 xx`       | `lea eax, [ebp+disp8]` | `&local`       | Load effective address.      |
| `50`             | `push eax`             | push           | Push register onto stack.    |
| `58`             | `pop eax`              | —              | Pop stack into eax.          |

---
## 3. Arithmetic & Logic

| *Hex*            | *Assembly*             | *C Equivalent*   | *Notes*               |
| ---------------- | ---------------------- | ---------------- | --------------------- |
| `03 45 xx`       | `add eax, [ebp+disp8]` | `eax += local;`  | Add local to eax.     |
| `2B 45 xx`       | `sub eax, [ebp+disp8]` | `eax -= local;`  | Sub local from eax.   |
| `05 xx xx xx xx` | `add eax, imm32`       | `eax += const;`  | Immediate add.        |
| `2D xx xx xx xx` | `sub eax, imm32`       | `eax -= const;`  | Immediate sub.        |
| `31 C0`          | `xor eax, eax`         | `eax = 0;`       | Common zeroing trick. |
| `35 xx xx xx xx` | `xor eax, imm32`       | `eax ^= const;`  | XOR operation.        |
| `25 xx xx xx xx` | `and eax, imm32`       | `eax &= const;`  | Bitwise AND.          |
| `0D xx xx xx xx` | `or eax, imm32`        | `eax             | = const;`             |
| `F7 D8`          | `neg eax`              | `eax = -eax;`    | Negate.               |
| `F7 E8`          | `imul eax`             | `eax *= eax;`    | Signed multiply.      |
| `99 F7 F9`       | `idiv ecx`             | `eax = eax/ecx;` | Signed division.      |

---
## 4. Control Flow (Jumps & Calls)

| *Hex*            | *Assembly*    | *C Equivalent*   | *Notes*                   |
| ---------------- | ------------- | ---------------- | ------------------------- |
| `E8 xx xx xx xx` | `call rel32`  | `func();`        | Call function at offset.  |
| `FF 15 xx...`    | `call [addr]` | `API();`         | Import call (IAT).        |
| `E9 xx xx xx xx` | `jmp rel32`   | `goto label;`    | Unconditional jump.       |
| `EB xx`          | `jmp rel8`    | `goto label;`    | Short unconditional jump. |
| `74 xx`          | `je rel8`     | `if (==) goto;`  | Jump if equal.            |
| `75 xx`          | `jne rel8`    | `if (!=) goto;`  | Jump if not equal.        |
| `7C xx`          | `jl rel8`     | `if (a<b) goto;` | Signed less.              |
| `7F xx`          | `jg rel8`     | `if (a>b) goto;` | Signed greater.           |
| `0F 84 xx...`    | `je rel32`    | `if (==) goto;`  | 32-bit near jump.         |
| `0F 85 xx...`    | `jne rel32`   | `if (!=) goto;`  | 32-bit near jump.         |

---
## 5. Memory Addressing

| *Hex*                  | *Assembly*                   | *C Equivalent*    | *Notes*                  |
| ---------------------- | ---------------------------- | ----------------- | ------------------------ |
| `8B 04 85 xx xx xx xx` | `mov eax, [ecx*4+disp32]`    | `eax = arr[ecx];` | Array access.            |
| `C7 45 xx yy yy yy yy` | `mov [ebp+disp8], imm32`     | `local = const;`  | Store constant in local. |
| `C6 45 xx yy`          | `mov byte [ebp+disp8], imm8` | `local = const;`  | Store 1 byte const.      |
| `8D 04 8D xx xx xx xx` | `lea eax, [ecx*4+disp32]`    | `&arr[ecx]`       | Effective address calc.  |

---
## 6. System & Special

| *Hex*   | *Assembly* | *C Equivalent* | *Notes*                  |
| ------- | ---------- | -------------- | ------------------------ |
| `CD 80` | `int 0x80` | `syscall(...)` | Linux 32-bit syscall.    |
| `0F 05` | `syscall`  | `syscall(...)` | Linux 64-bit syscall.    |
| `0F 34` | `sysenter` | `syscall(...)` | Windows fast call (XP+). |
| `F4`    | `hlt`      | —              | Halt CPU.                |
| `FA`    | `cli`      | —              | Clear interrupts.        |
| `FB`    | `sti`      | —              | Set interrupts.          |
| `0F A2` | `cpuid`    | —              | Query CPU info.          |
| `0F 31` | `rdtsc`    | —              | Read time-stamp counter. |

---

Sources: 
Intel® 64 and IA-32 Architectures Software Developer’s Manual, Vol. 2 (Instruction Set Reference)  
_Reverse Engineering for Beginners_ — Dennis Yurichev (free PDF)  
Personal RE practice and notes (SkyWolf-re)
