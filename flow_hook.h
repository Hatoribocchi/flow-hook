#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <cstring>

#define NMD_ASSEMBLY_IMPLEMENTATION
#include "nmd_assembly.h"

namespace FH
{
    class CHookObject
    {
    public:
        CHookObject() = default;

        CHookObject(uintptr_t uBaseFnAddress, uintptr_t uReplaceFnAddress) :
            pBaseFn(reinterpret_cast<uint8_t*>(uBaseFnAddress)),
            pReplaceFn(reinterpret_cast<uint8_t*>(uReplaceFnAddress)) {}

        bool CreateHook()
        {
            DWORD nLength = 0;

            uint8_t* pOpCode = pBaseFn;

            const bool bIsX86Mode = sizeof(uintptr_t) == 0x4u;
            const size_t MinimalSize = bIsX86Mode ? 5 : 14;

            while (pOpCode - pBaseFn < MinimalSize)
            {
                const size_t nInstructionLength = nmd_x86_ldisasm(
                    pBaseFn + nLength,
                    15,
                    bIsX86Mode ? NMD_X86_MODE_32 : NMD_X86_MODE_64
                );

                if (nInstructionLength == 0x0u)
                    return false;

                nLength += static_cast<DWORD>(nInstructionLength);
                pOpCode = pBaseFn + nLength;
            }

            if (nLength < MinimalSize)
                return false;

            vecOriginalBytes.assign(pBaseFn, pBaseFn + nLength);

            LPVOID pReturnMem = VirtualAlloc(nullptr, nLength + MinimalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pReturnMem == nullptr) 
                return false;

            memcpy(pReturnMem, vecOriginalBytes.data(), nLength);

            uint8_t* pTrampoline = static_cast<uint8_t*>(pReturnMem);

            if (bIsX86Mode)
            {
                pTrampoline[nLength] = 0xE9u;

                *reinterpret_cast<uint32_t*>(pTrampoline + nLength + 0x1u) =
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pBaseFn + nLength) -
                        reinterpret_cast<uintptr_t>(pTrampoline + nLength + 0x5u));
            }
            else
            {
                
            }

            DWORD dwOldProtect = 0x0u;
            if (!VirtualProtect(pBaseFn, nLength, PAGE_EXECUTE_READWRITE, &dwOldProtect))
                return false;

            if (bIsX86Mode)
            {
                pBaseFn[0x0u] = 0xE9u;

                *reinterpret_cast<uint32_t*>(pBaseFn + 0x1u) =
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pReplaceFn) -
                        reinterpret_cast<uintptr_t>(pBaseFn) - 0x5u);
            }
            else
            {
                
            }

            for (DWORD i = MinimalSize; i < nLength; ++i)
                pBaseFn[i] = 0x90u;

            VirtualProtect(pBaseFn, nLength, dwOldProtect, &dwOldProtect);

            pOriginalFn = reinterpret_cast<uint8_t*>(pReturnMem);
            return true;
        }

        void RemoveHook()
        {
            if (vecOriginalBytes.empty())
                return;

            DWORD dwOldProtect = 0x0u;

            if (!VirtualProtect(pBaseFn, vecOriginalBytes.size(), PAGE_EXECUTE_READWRITE, &dwOldProtect))
                return;

            memcpy(pBaseFn, vecOriginalBytes.data(), vecOriginalBytes.size());

            VirtualProtect(pBaseFn, vecOriginalBytes.size(), dwOldProtect, &dwOldProtect);

            if (pOriginalFn != nullptr)
                VirtualFree(pOriginalFn, 0, MEM_RELEASE);
        }

        template <typename Fn>
        Fn GetOriginal()
        {
            return reinterpret_cast<Fn>(pOriginalFn);
        }

    private:
        uint8_t* pBaseFn{ nullptr };
        uint8_t* pReplaceFn{ nullptr };
        uint8_t* pOriginalFn{ nullptr };
        std::vector<uint8_t> vecOriginalBytes;
    };
}
