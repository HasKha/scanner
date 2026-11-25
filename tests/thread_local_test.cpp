#include <windows.h>
#include <intrin.h>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <latch>
#include <thread>

#include "scanner/thread_local.h"

using namespace scanner;

namespace {

int main_thread_value = 1;
int other_thread_value = 2;
thread_local void* pointer = nullptr;

// Where `pointer` is in the executable's TLS block, as a scan of the code that reads it would give.
uint32_t offsetInBlock(const Image& image) {
    const uint32_t index = *(const uint32_t*)image.tlsIndexAddress();
    const auto* const* tls_array = (const uint8_t* const*)__readgsqword(0x58);
    return (uint32_t)((const uint8_t*)&pointer - tls_array[index]);
}

} // namespace

TEST_CASE("a thread-local is read in the thread that holds the one wanted") {
    const Image* image = Image::running();
    REQUIRE(image != nullptr);
    REQUIRE(image->tlsIndexAddress() != 0);
    const uint32_t offset = offsetInBlock(*image);

    pointer = &main_thread_value;
    std::latch set(1);
    std::latch done(1);
    std::atomic<DWORD> other_id{0};
    std::thread other([&] {
        pointer = &other_thread_value;
        other_id = GetCurrentThreadId();
        set.count_down();
        done.wait();
    });
    set.wait();

    // Found by the walk, whichever thread it opens first.
    ThreadLocalPointer others(image, offset, [](void* candidate) { return candidate == &other_thread_value; });
    CHECK(others.get() == &other_thread_value);
    CHECK(others.get() == &other_thread_value);

    // The thread named first holds one `accept` refuses, and the walk goes on to ours.
    ThreadLocalPointer ours(image, offset, [](void* candidate) { return candidate == &main_thread_value; });
    CHECK(ours.get(other_id) == &main_thread_value);

    ThreadLocalPointer refused(image, offset, [](void*) { return false; });
    CHECK(refused.get() == nullptr);
    ThreadLocalPointer unscanned(image, std::nullopt, [](void*) { return true; });
    CHECK(unscanned.get() == nullptr);

    done.count_down();
    other.join();
}
