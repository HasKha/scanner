#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "scanner/image.h"

namespace scanner {

// The `size` bytes at `at` in this process, copied into `into`; false when any of them cannot be read.
bool readMemory(const void* at, void* into, size_t size);

// A copy of the `T` at `at` in this process, or none when it cannot be read: for a pointer nothing vouches for yet, which
// another thread may free as it is read, or which may not be what it is taken for.
template <typename T>
std::optional<T> readMemory(const void* at) {
    T copy{};
    if (!readMemory(at, &copy, sizeof(T))) {
        return std::nullopt;
    }
    return copy;
}

// A pointer the running executable keeps in a static thread-local, as `thread_local T* x;` would, read from outside the
// threads that hold it: each thread has its own, and one of them holds the one wanted. Its offset in the executable's
// TLS block is what a scan of the code that reads it gives, and `accept` says whether a thread's pointer is the one.
//
// A thread's TEB holds its TLS array at +0x58, and the executable's block is the one at its TLS index. Every read of
// another thread's goes through readMemory(). x64 only.
class ThreadLocalPointer {
public:
    // Whether `candidate`, never null, is the pointer wanted: it should prove it through readMemory().
    using Accept = bool (*)(void* candidate);

    // `image`: Image::running(). With no image, no offset, or an executable that has no thread-locals, get() answers
    // null.
    ThreadLocalPointer(const Image* image, std::optional<uint32_t> offset, Accept accept);

    // Thread: any. The pointer, or null while no thread holds one `accept` takes. `first_thread`, when not zero, is
    // looked in before the others. The first found is kept; until then the process's threads are walked at most once a
    // second, as a walk opens every one, and the calls between answer null.
    void* get(uint32_t first_thread = 0);

private:
    void* readThread(uint32_t thread_id) const;

    std::optional<uint32_t> offset;
    std::optional<uint32_t> tls_index;
    Accept accept;
    std::atomic<void*> found{nullptr};
    std::atomic<uint64_t> next_try_ms{0};
};

} // namespace scanner
