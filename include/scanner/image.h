#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "scanner/pattern.h"

namespace scanner {

// An executable's file, mapped read-only, scanned for patterns. Nothing in it runs, is relocated or imported, and the
// process's memory is never read to scan, so:
//
// - **Only the executable is scanned.** Another module's code is never looked at, nor a page of it that the module's
//   unloading takes away mid-scan.
// - **What another module did to the executable's code is not seen.** A detour over a function's entry leaves its pattern
//   matching.
// - **The file on disk is scanned exactly as the running image is**, so a pattern is checked with the program shut, at
//   the addresses a disassembler shows.
//
// Every read a step makes is bounded by the file: a step that would read past it rejects the site rather than fault. A
// page of the mapping the system cannot read in, from a drive gone or a file changed under it, is a miss for scan(),
// which the program scans with; scanAll() and findPattern(), for checking a pattern, let the fault through to the caller.
// Nothing is specific to any one program. A const Image is safe to use from any thread.
class Image {
public:
    // The executable this process was started from. Its file is checked against the image the loader made of it, by
    // their headers, and a scan's answer is an address in that image.
    static std::optional<Image> openRunning(std::string& why);

    // openRunning(), once for the whole process and kept to its end: the mapping every scan of the process can share.
    // Null when it could not be opened, and `why`, when given, says why. Safe from any thread.
    static const Image* running(std::string* why = nullptr);

    // An executable on disk. A scan's answer is an address as if it were loaded where it asks to be, which is what a
    // disassembler shows.
    static std::optional<Image> openFile(const std::filesystem::path& path, std::string& why);

    // ---- Scanning

    // Where `scan` lands from its lowest site whose steps can all be taken. Null when none can.
    void* scan(const PatternScan& scan) const;
    // The first of the scans that lands anywhere, where it lands.
    void* scan(const FallbackScan& scans) const;

    template <typename T, typename Scan>
    T scan(const Scan& scans) const {
        return (T)scan(scans);
    }

    // A site of a pattern, and where its steps took it. For checking a pattern, in full.
    struct Site {
        uintptr_t match = 0;
        // Zero when a step could not be taken, and `rejected` says which and why.
        uintptr_t landed = 0;
        std::string rejected;
    };
    // Every site `scan`'s pattern matches, lowest first: scan() takes the first that landed.
    std::vector<Site> scanAll(const PatternScan& scan) const;

    // Every place in the code the pattern alone matches, lowest first.
    std::vector<uintptr_t> findPattern(const Pattern& pattern) const;

    // ---- Where things are

    // A part of the image, and the bytes the file holds of it.
    struct Section {
        uint32_t rva = 0;
        uint32_t virtual_size = 0;
        // The bytes the file holds of it, from `rva`: past them, the image is zeroes the file does not hold.
        uint32_t file_size = 0;
        const uint8_t* bytes = nullptr;
        bool code = false;
        bool writable = false;
    };
    // The headers, as the file holds them, at rva 0.
    const Section& headers() const { return regions.front(); }
    // The file's sections, in its order.
    std::span<const Section> sections() const { return std::span(regions).subspan(1); }

    uintptr_t liveBase() const { return live_base; }
    size_t size() const { return image_size; }
    bool contains(uintptr_t live, size_t count = 1) const;
    bool isCode(uintptr_t live) const;
    // What a disassembler shows for `live`: the address the file asks to be loaded at, plus its offset in the image.
    uint64_t preferredAddress(uintptr_t live) const { return preferred_base + (live - live_base); }
    // Where the loader keeps the executable's TLS index, `_tls_index`, which names its block in each thread's TLS array:
    // the TLS directory's AddressOfIndex. Zero when it has no thread-locals. x64 only.
    uintptr_t tlsIndexAddress() const { return tls_index_rva != 0 ? live_base + tls_index_rva : 0; }

private:
    Image() = default;

    struct Walk {
        std::optional<int64_t> landed;
        std::string rejected;
    };

    // The file's `count` bytes at `rva`, when one section, or the headers, holds all of them.
    const uint8_t* fileBytes(int64_t rva, size_t count) const;
    // Calls `visit` at each site of `pattern` in the code, lowest first, until it returns true.
    template <typename Visit>
    void visitSites(const Pattern& pattern, Visit visit) const;
    // `explain`: whether to say why a site is rejected, which only scanAll() wants.
    Walk walk(const PatternScan& scan, uint32_t site, bool explain) const;
    // scan(), unguarded: __try needs a frame of its own, with no objects to destroy.
    void* firstLanding(const PatternScan& scan) const;
    std::string describe(int64_t rva) const;

    struct Unmap {
        void operator()(const void* view) const;
    };
    std::unique_ptr<const void, Unmap> view;
    size_t image_size = 0;
    uint64_t preferred_base = 0;
    uintptr_t live_base = 0;
    // The headers, then the file's sections.
    std::vector<Section> regions;
    // The unwind table's entries, ascending, x64 only: three uint32 each, a function's start, end and unwind data.
    const uint32_t* functions = nullptr;
    size_t function_count = 0;
    uint32_t tls_index_rva = 0;
};

} // namespace scanner
