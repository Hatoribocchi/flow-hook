Trampoline hooking library (only x86 for now)

```
 bool SetupHooks()
{
    uintptr_t uOriginalFunction = 0x12345678;
    uintptr_t uNewFunction = 0x87654321;

    FH::CHookObject Detour(uOriginalFunction, uNewFunction);
    if (!Detour.CreateHook())
        return false;

    return true;
}
```

Dependencies: Nmd disassembler - https://github.com/Nomade040/nmd
