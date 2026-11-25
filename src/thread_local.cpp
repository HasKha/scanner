#include "scanner/thread_local.h"

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

namespace scanner {

bool readMemory(const void* at, void* into, size_t size) {
    SIZE_T read = 0;
    return at != nullptr && ReadProcessMemory(GetCurrentProcess(), at, into, size, &read) && read == size;
}

ThreadLocalPointer::ThreadLocalPointer(const Image* image, std::optional<uint32_t> offset, Accept accept)
    : offset(offset), accept(accept) {
    // Written by the loader before any code of the executable runs, and never again.
    const uintptr_t index_at = image != nullptr ? image->tlsIndexAddress() : 0;
    tls_index = index_at != 0 ? readMemory<uint32_t>((const void*)index_at) : std::nullopt;
}

void* ThreadLocalPointer::readThread(uint32_t thread_id) const {
    constexpr size_t TEB_TLS_ARRAY = 0x58;
    const HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, thread_id);
    if (thread == nullptr) {
        return nullptr;
    }
    // THREAD_BASIC_INFORMATION, which winternl.h does not define, asked for by its class, 0.
    struct ThreadBasicInformation {
        NTSTATUS exit_status;
        void* teb;
        struct {
            HANDLE process;
            HANDLE thread;
        } client_id;
        KAFFINITY affinity;
        LONG priority;
        LONG base_priority;
    } basic{};
    const NTSTATUS status = NtQueryInformationThread(thread, (THREADINFOCLASS)0, &basic, sizeof(basic), nullptr);
    CloseHandle(thread);
    if (status != 0) {
        return nullptr;
    }

    const auto tls_array = readMemory<const uint8_t* const*>((const uint8_t*)basic.teb + TEB_TLS_ARRAY);
    const auto block = tls_array ? readMemory<const uint8_t*>(*tls_array + *tls_index) : std::nullopt;
    const auto candidate = block ? readMemory<void*>(*block + *offset) : std::nullopt;
    return candidate && *candidate != nullptr && accept(*candidate) ? *candidate : nullptr;
}

void* ThreadLocalPointer::get(uint32_t first_thread) {
    if (void* pointer = found.load(std::memory_order_acquire)) {
        return pointer;
    }
    if (!offset || !tls_index) {
        return nullptr;
    }
    constexpr uint64_t RETRY_MS = 1000;
    const uint64_t now_ms = GetTickCount64();
    uint64_t next_ms = next_try_ms.load(std::memory_order_relaxed);
    if (now_ms < next_ms || !next_try_ms.compare_exchange_strong(next_ms, now_ms + RETRY_MS, std::memory_order_relaxed)) {
        return nullptr;
    }

    void* pointer = first_thread != 0 ? readThread(first_thread) : nullptr;
    if (pointer == nullptr) {
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);
            for (BOOL more = Thread32First(snapshot, &entry); more && pointer == nullptr; more = Thread32Next(snapshot, &entry)) {
                if (entry.th32OwnerProcessID == GetCurrentProcessId() && entry.th32ThreadID != first_thread) {
                    pointer = readThread(entry.th32ThreadID);
                }
            }
            CloseHandle(snapshot);
        }
    }
    found.store(pointer, std::memory_order_release);
    return pointer;
}

} // namespace scanner
