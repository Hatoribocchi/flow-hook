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
    /**
     * @class CHookObject
     * Represents a hook object for injecting replacement code into a function
     */
    class CHookObject
    {
    public:
        // Default constructor
        CHookObject() = default;

        /**
         * @brief Constructor to initialize the base and replacement functions
         * @param uBaseFnAddress Address of the function to hook
         * @param uReplaceFnAddress Address of the replacement function
         */
        CHookObject(uintptr_t uBaseFnAddress, uintptr_t uReplaceFnAddress) :
            pBaseFn(reinterpret_cast<uint8_t*>(uBaseFnAddress)),
            pReplaceFn(reinterpret_cast<uint8_t*>(uReplaceFnAddress)) {}

        /**
         * @brief Creates a hook by overwriting the original function with a jump to the replacement
         * @return true if the hook was created successfully, false otherwise
         */
        bool CreateHook()
        {
            // Length of the overwritten instructions
            DWORD nLength = 0;

            // Pointer to the current opcode being processed
            uint8_t* pOpCode = pBaseFn;

            // Get cpu mode by check size of uintprt
            const bool bIsX86Mode = sizeof(uintptr_t) == 0x4u;

            // Get minimal byte size for current cpu mode
            const size_t MinimalSize = bIsX86Mode ? 5 : 14;

            // Calculate the minimum length of the instructions to overwrite
            while (pOpCode - pBaseFn < MinimalSize)
            {
                // Disassemble the next instruction to get its length
                const size_t nInstructionLength = nmd_x86_ldisasm(
                    pBaseFn + nLength,
                    15,
                    bIsX86Mode ? NMD_X86_MODE_32 : NMD_X86_MODE_64
                );

                // If the instruction length is zero, disassembly failed
                if (nInstructionLength == 0x0u)
                    return false;

                // Accumulate the instruction length and advance the pointer
                nLength += static_cast<DWORD>(nInstructionLength);
                pOpCode = pBaseFn + nLength;
            }

            // If less than minimal size of bytes, we cannot create a hook
            if (nLength < MinimalSize)
                return false;

            // Save the original instructions
            vecOriginalBytes.assign(pBaseFn, pBaseFn + nLength);

            // Allocate executable memory for the trampoline (original instructions + jump back)
            LPVOID pReturnMem = VirtualAlloc(nullptr, nLength + MinimalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pReturnMem == nullptr) 
                return false;

            // Copy the original instructions to the trampoline memory
            memcpy(pReturnMem, vecOriginalBytes.data(), nLength);

            // Add a jump at the end of the trampoline back to the remainder of the original function
            uint8_t* pTrampoline = static_cast<uint8_t*>(pReturnMem);

            // x86 mode
            if (bIsX86Mode)
            {
                // Opcode for a relative jump
                pTrampoline[nLength] = 0xE9u;

                // Calculate the relative offset for the jump instruction at the end of the trampoline
                *reinterpret_cast<uint32_t*>(pTrampoline + nLength + 0x1u) =
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pBaseFn + nLength) -
                        reinterpret_cast<uintptr_t>(pTrampoline + nLength + 0x5u));
            }
            // x64 mode
            else
            {
                // TODO: Add x64 support
            }

            // Modify the original function to jump to the replacement function
            DWORD dwOldProtect = 0x0u;

            // Change memory protection
            if (!VirtualProtect(pBaseFn, nLength, PAGE_EXECUTE_READWRITE, &dwOldProtect))
                return false;

            // x86 mode
            if (bIsX86Mode)
            {
                // Write a relative jump opcode at the start of the function
                pBaseFn[0x0u] = 0xE9u;

                //Calculate the relative offset for the jump instruction that redirects the execution
                //from the original function (pBaseFn) to the replacement function (pReplaceFn)
                *reinterpret_cast<uint32_t*>(pBaseFn + 0x1u) =
                    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pReplaceFn) -
                        reinterpret_cast<uintptr_t>(pBaseFn) - 0x5u);
            }
            // x64 mode
            else
            {
                // TODO: Add x64 support
            }

            // Fill remaining bytes with NOP instructions
            for (DWORD i = MinimalSize; i < nLength; ++i)
                pBaseFn[i] = 0x90u;

            // Restore the original protection of the memory
            VirtualProtect(pBaseFn, nLength, dwOldProtect, &dwOldProtect);

            // Store the trampoline address as the original function
            pOriginalFn = reinterpret_cast<uint8_t*>(pReturnMem);
            return true;
        }

        /**
         * @brief Removes the hook and restores the original function
         */
        void RemoveHook()
        {
            // Check if the original bytes have been saved. If the backup is empty, there is no hook to remove
            if (vecOriginalBytes.empty())
                return;

            // Variable to store the previous protection flags
            DWORD dwOldProtect = 0x0u;

            // Attempt to change the memory protection of the original function to allow writing
            if (!VirtualProtect(pBaseFn, vecOriginalBytes.size(), PAGE_EXECUTE_READWRITE, &dwOldProtect))
                return;

            // Restore the original bytes of the function from the backup
            memcpy(pBaseFn, vecOriginalBytes.data(), vecOriginalBytes.size());

            // Restore the original memory protection flags for the function
            VirtualProtect(pBaseFn, vecOriginalBytes.size(), dwOldProtect, &dwOldProtect);

            // If the trampoline memory was allocated, free it
            if (pOriginalFn != nullptr)
                VirtualFree(pOriginalFn, 0, MEM_RELEASE);
        }

        /**
         * @brief Gets the original function pointer
         * @tparam Fn Type of the original function
         * @return Pointer to the trampoline function
         */
        template <typename Fn>
        Fn GetOriginal()
        {
            return reinterpret_cast<Fn>(pOriginalFn);
        }

    private:
        uint8_t* pBaseFn = nullptr;
        uint8_t* pReplaceFn = nullptr;
        uint8_t* pOriginalFn = nullptr;
        std::vector<uint8_t> vecOriginalBytes;
    };
}
