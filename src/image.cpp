#include "scanner/image.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <format>

namespace scanner {

namespace {

struct Handle {
    HANDLE handle;
    ~Handle() {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

// What the headers say, from either kind of optional header.
struct Headers {
    const IMAGE_FILE_HEADER* file = nullptr;
    uint64_t image_base = 0;
    uint32_t image_size = 0;
    uint32_t headers_size = 0;
    uint32_t checksum = 0;
    uint32_t entry_point = 0;
    const IMAGE_DATA_DIRECTORY* directories = nullptr;
    uint32_t directory_count = 0;
    const IMAGE_SECTION_HEADER* sections = nullptr;
};

// The headers of the `size` bytes at `start`, every one of them inside the bytes. Null, saying why, when they are not
// an executable's.
std::optional<Headers> readHeaders(const uint8_t* start, size_t size, std::string& why) {
    const auto holds = [size](size_t offset, size_t count) { return offset <= size && count <= size - offset; };
    if (!holds(0, sizeof(IMAGE_DOS_HEADER)) || ((const IMAGE_DOS_HEADER*)start)->e_magic != IMAGE_DOS_SIGNATURE) {
        why = "not an executable";
        return std::nullopt;
    }
    const size_t nt_offset = (size_t)((const IMAGE_DOS_HEADER*)start)->e_lfanew;
    constexpr size_t SIGNATURE_AND_FILE_HEADER = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!holds(nt_offset, SIGNATURE_AND_FILE_HEADER + sizeof(WORD)) || *(const DWORD*)(start + nt_offset) != IMAGE_NT_SIGNATURE) {
        why = "not an executable: no PE header";
        return std::nullopt;
    }

    Headers headers;
    headers.file = (const IMAGE_FILE_HEADER*)(start + nt_offset + sizeof(DWORD));
    const size_t optional_offset = nt_offset + SIGNATURE_AND_FILE_HEADER;
    const size_t optional_size = headers.file->SizeOfOptionalHeader;
    const WORD magic = *(const WORD*)(start + optional_offset);
    const auto read = [&](const auto* optional) {
        headers.image_base = optional->ImageBase;
        headers.image_size = optional->SizeOfImage;
        headers.headers_size = optional->SizeOfHeaders;
        headers.checksum = optional->CheckSum;
        headers.entry_point = optional->AddressOfEntryPoint;
        headers.directories = optional->DataDirectory;
        headers.directory_count = std::min<uint32_t>(optional->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    };
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && optional_size >= sizeof(IMAGE_OPTIONAL_HEADER64) &&
        holds(optional_offset, sizeof(IMAGE_OPTIONAL_HEADER64))) {
        read((const IMAGE_OPTIONAL_HEADER64*)(start + optional_offset));
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && optional_size >= sizeof(IMAGE_OPTIONAL_HEADER32) &&
               holds(optional_offset, sizeof(IMAGE_OPTIONAL_HEADER32))) {
        read((const IMAGE_OPTIONAL_HEADER32*)(start + optional_offset));
    } else {
        why = "not an executable: its optional header is not one";
        return std::nullopt;
    }

    const size_t sections_offset = optional_offset + optional_size;
    if (!holds(sections_offset, (size_t)headers.file->NumberOfSections * sizeof(IMAGE_SECTION_HEADER))) {
        why = "not an executable: its section table is cut short";
        return std::nullopt;
    }
    headers.sections = (const IMAGE_SECTION_HEADER*)(start + sections_offset);
    return headers;
}

std::wstring moduleFileName(HMODULE module) {
    std::wstring name(MAX_PATH, L'\0');
    DWORD length = GetModuleFileNameW(module, name.data(), (DWORD)name.size());
    while (length == name.size()) {
        name.resize(name.size() * 2);
        length = GetModuleFileNameW(module, name.data(), (DWORD)name.size());
    }
    name.resize(length);
    return name;
}

std::string hex(uint64_t value) { return std::format("0x{:X}", value); }

} // namespace

void Image::Unmap::operator()(const void* view) const { UnmapViewOfFile(view); }

std::optional<Image> Image::openFile(const std::filesystem::path& path, std::string& why, uintptr_t live_base) {
    // ---- The file, mapped read-only: its pages are the file's, and nothing is copied
    const Handle file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    LARGE_INTEGER file_size{};
    if (file.handle == INVALID_HANDLE_VALUE || !GetFileSizeEx(file.handle, &file_size) || file_size.QuadPart == 0) {
        why = std::format("cannot read {}, error {}", path.string(), GetLastError());
        return std::nullopt;
    }
    const Handle mapping{CreateFileMappingW(file.handle, nullptr, PAGE_READONLY, 0, 0, nullptr)};
    const void* mapped = mapping.handle != nullptr ? MapViewOfFile(mapping.handle, FILE_MAP_READ, 0, 0, 0) : nullptr;
    if (mapped == nullptr) {
        why = std::format("cannot map {}, error {}", path.string(), GetLastError());
        return std::nullopt;
    }
    Image image;
    image.view.reset(mapped);
    const auto* start = (const uint8_t*)mapped;
    const size_t size = (size_t)file_size.QuadPart;

    const std::optional<Headers> headers = readHeaders(start, size, why);
    if (!headers) {
        why = path.string() + " is " + why;
        return std::nullopt;
    }
    image.image_size = headers->image_size;
    image.preferred_base = headers->image_base;
    image.live_base = live_base != 0 ? live_base : (uintptr_t)headers->image_base;
    image.has_live = live_base != 0;

    // ---- The sections, the headers first as one of their own
    image.sections.push_back({0, headers->headers_size, std::min<uint32_t>(headers->headers_size, (uint32_t)std::min<size_t>(size, UINT32_MAX)), start, false});
    for (WORD i = 0; i < headers->file->NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER& header = headers->sections[i];
        // Zero from a linker that leaves the raw size to say it.
        const uint32_t virtual_size = header.Misc.VirtualSize != 0 ? header.Misc.VirtualSize : header.SizeOfRawData;
        const uint32_t held = std::min<uint32_t>(header.SizeOfRawData, virtual_size);
        if ((uint64_t)header.PointerToRawData + held > size || (uint64_t)header.VirtualAddress + virtual_size > image.image_size) {
            why = std::format("{} is cut short: section {} lies past its end", path.string(), i);
            return std::nullopt;
        }
        image.sections.push_back({header.VirtualAddress, virtual_size, held, start + header.PointerToRawData,
                                  (header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0});
    }

    // ---- What the loader relocates
    if (headers->directory_count > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        const IMAGE_DATA_DIRECTORY& directory = headers->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        const uint8_t* block = image.fileBytes(directory.VirtualAddress, directory.Size);
        const uint8_t* const end = block != nullptr ? block + directory.Size : nullptr;
        while (block != nullptr && block + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            const auto* relocation = (const IMAGE_BASE_RELOCATION*)block;
            const size_t block_size = relocation->SizeOfBlock;
            if (block_size < sizeof(IMAGE_BASE_RELOCATION) || block + block_size > end) {
                block = nullptr;
            } else {
                const auto* entry = (const WORD*)(block + sizeof(IMAGE_BASE_RELOCATION));
                const auto* const entries_end = (const WORD*)(block + block_size);
                for (; entry < entries_end; ++entry) {
                    const int type = *entry >> 12;
                    const uint32_t rva = relocation->VirtualAddress + (*entry & 0xFFF);
                    if (type == IMAGE_REL_BASED_DIR64) {
                        image.relocations.push_back({rva, 8});
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        image.relocations.push_back({rva, 4});
                    }
                }
                block += block_size;
            }
        }
        std::ranges::sort(image.relocations, {}, &Relocation::rva);
    }

    // ---- The unwind table, for FuncEntry()
    if (headers->file->Machine == IMAGE_FILE_MACHINE_AMD64 && headers->directory_count > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        const IMAGE_DATA_DIRECTORY& directory = headers->directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        constexpr size_t ENTRY_SIZE = 3 * sizeof(uint32_t);
        image.functions = (const uint32_t*)image.fileBytes(directory.VirtualAddress, directory.Size);
        image.function_count = image.functions != nullptr ? directory.Size / ENTRY_SIZE : 0;
    }
    return image;
}

std::optional<Image> Image::openRunning(std::string& why) {
    const HMODULE module = GetModuleHandleW(nullptr);
    const std::wstring path = moduleFileName(module);
    std::optional<Image> image = openFile(path, why, (uintptr_t)module);
    if (!image) {
        return std::nullopt;
    }

    // The file is the one the process was started from while the headers the loader keeps agree with it: a client
    // updated on disk while it runs does not.
    std::string unused;
    const Section& headers = image->sections.front();
    const std::optional<Headers> live = readHeaders((const uint8_t*)module, headers.virtual_size, unused);
    const std::optional<Headers> file = readHeaders(headers.bytes, headers.file_size, unused);
    const bool same = live && file && live->file->TimeDateStamp == file->file->TimeDateStamp &&
                      live->file->NumberOfSections == file->file->NumberOfSections && live->image_size == file->image_size &&
                      live->checksum == file->checksum && live->entry_point == file->entry_point;
    if (!same) {
        why = std::filesystem::path(path).string() + " is not the file this process was started from: their headers differ";
        return std::nullopt;
    }
    return image;
}

const uint8_t* Image::fileBytes(int64_t rva, size_t count) const {
    for (const Section& section : sections) {
        if (rva >= section.rva && (uint64_t)(rva - section.rva) + count <= section.file_size) {
            return section.bytes + (rva - section.rva);
        }
    }
    return nullptr;
}

template <typename Visit>
void Image::visitSites(const Pattern& pattern, Visit visit) const {
    // The first byte the pattern names, to skip to with memchr() rather than compare at every address.
    size_t first_named = 0;
    while (first_named < pattern.size() && pattern[first_named].wildcard) {
        ++first_named;
    }
    const bool any_named = first_named < pattern.size();
    bool stopped = !pattern.valid();
    for (const Section& section : sections) {
        const bool holds_sites = section.code && section.file_size >= pattern.size();
        const uint8_t* const last_site = holds_sites ? section.bytes + (section.file_size - pattern.size()) : nullptr;
        const uint8_t* site = section.bytes;
        while (holds_sites && !stopped && site <= last_site) {
            if (any_named) {
                const auto* found = (const uint8_t*)std::memchr(site + first_named, pattern[first_named].value, last_site - site + 1);
                site = found != nullptr ? found - first_named : last_site + 1;
            }
            if (site <= last_site && pattern.matches(site)) {
                stopped = visit(section.rva + (uint32_t)(site - section.bytes));
            }
            ++site;
        }
    }
}

Image::Walk Image::walk(const PatternScan& scan, uint32_t site, bool explain) const {
    Walk walk;
    int64_t at = site;
    int64_t offset_from_match = 0;
    std::vector<int64_t> stored;

    // Where the rel32 at `at` points, when it can be read and points inside the image.
    const auto follow = [this](int64_t from) -> std::optional<int64_t> {
        const uint8_t* bytes = fileBytes(from, sizeof(int32_t));
        if (bytes == nullptr) {
            return std::nullopt;
        }
        int32_t displacement = 0;
        std::memcpy(&displacement, bytes, sizeof(displacement));
        const int64_t target = from + (int64_t)sizeof(int32_t) + displacement;
        return target >= 0 && (uint64_t)target < image_size ? std::optional(target) : std::nullopt;
    };
    const auto names = [this, &follow](int64_t from, const void* text, size_t text_size) {
        const std::optional<int64_t> target = follow(from);
        const uint8_t* bytes = target ? fileBytes(*target, text_size) : nullptr;
        return bytes != nullptr && std::memcmp(bytes, text, text_size) == 0;
    };
    const auto compare = [this, &walk, &at, explain](size_t width, int64_t wanted) {
        const uint8_t* bytes = fileBytes(at, width);
        uint64_t read = 0;
        if (bytes != nullptr) {
            std::memcpy(&read, bytes, width);
        }
        const uint64_t mask = width == 8 ? ~0ull : (1ull << (width * 8)) - 1;
        const bool same = bytes != nullptr && read == ((uint64_t)wanted & mask);
        if (!same && explain) {
            walk.rejected = bytes != nullptr ? std::format("{} reads {}, we say {}", describe(at), hex(read), hex((uint64_t)wanted & mask))
                                             : describe(at) + " is not in the file";
        }
        return same;
    };

    bool passed = true;
    for (size_t i = 0; i < scan.step_count && passed; ++i) {
        const Step& step = scan.steps[i];
        switch (step.kind) {
        case StepKind::Offset:
            offset_from_match += step.value;
            at += step.value;
            break;
        case StepKind::Follow: {
            const std::optional<int64_t> target = follow(at);
            passed = target.has_value();
            if (passed) {
                at = *target;
            } else if (explain) {
                walk.rejected = "the rel32 at " + describe(at) + " points outside the image";
            }
            break;
        }
        case StepKind::Strcmp:
            passed = names(at, step.text, std::strlen(step.text) + 1);
            if (!passed && explain) {
                walk.rejected = std::format("{} does not name \"{}\"", describe(at), step.text);
            }
            break;
        case StepKind::Wcscmp:
            passed = names(at, step.wide_text, (std::wcslen(step.wide_text) + 1) * sizeof(wchar_t));
            if (!passed && explain) {
                walk.rejected = describe(at) + " does not name the wide text wanted";
            }
            break;
        case StepKind::CmpI8: passed = compare(1, step.value); break;
        case StepKind::CmpI16: passed = compare(2, step.value); break;
        case StepKind::CmpI32: passed = compare(4, step.value); break;
        case StepKind::CmpI64: passed = compare(8, step.value); break;
        case StepKind::PushAddr: stored.push_back(at); break;
        case StepKind::PopAddr:
            passed = !stored.empty();
            if (passed) {
                at = stored.back();
                stored.pop_back();
            } else if (explain) {
                walk.rejected = "PopAddr() with nothing pushed";
            }
            break;
        case StepKind::AdvWcard: {
            const auto size = (int64_t)scan.pattern.size();
            passed = offset_from_match >= 0 && offset_from_match <= size;
            for (int64_t set = 0; set < step.value && passed; ++set) {
                bool was_at_wildcard = offset_from_match < size && scan.pattern[(size_t)offset_from_match].wildcard;
                bool found = false;
                while (offset_from_match < size && !found) {
                    const bool is_wildcard = scan.pattern[(size_t)offset_from_match].wildcard;
                    found = !was_at_wildcard && is_wildcard;
                    if (!found) {
                        was_at_wildcard = was_at_wildcard && is_wildcard;
                        ++offset_from_match;
                    }
                }
            }
            if (passed) {
                at = site + offset_from_match;
            } else if (explain) {
                walk.rejected = std::format("AdvWcard() from {} bytes into a pattern of {}", offset_from_match, size);
            }
            break;
        }
        case StepKind::FuncEntry: {
            const auto rva = (uint32_t)at;
            const uint32_t* const end = functions + function_count * 3;
            // The last entry starting at or before `at`, by binary search over entries three uint32s wide.
            size_t low = 0;
            size_t high = function_count;
            while (low < high) {
                const size_t middle = (low + high) / 2;
                if (functions[middle * 3] <= rva) {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            const uint32_t* entry = low > 0 ? functions + (low - 1) * 3 : end;
            passed = at >= 0 && entry != end && rva < entry[1];
            if (passed) {
                at = entry[0];
            } else if (explain) {
                walk.rejected = describe(at) + " is in no function the unwind table knows";
            }
            break;
        }
        }
    }
    if (passed) {
        walk.landed = at;
    }
    return walk;
}

std::string Image::describe(int64_t rva) const { return hex(preferred_base + rva); }

void* Image::scan(const PatternScan& scan) const {
    void* landed = nullptr;
    visitSites(scan.pattern, [&](uint32_t site) {
        const Walk walked = walk(scan, site, false);
        if (walked.landed) {
            landed = (void*)(live_base + *walked.landed);
        }
        return walked.landed.has_value();
    });
    return landed;
}

void* Image::scan(const FallbackScan& scans) const {
    void* landed = nullptr;
    for (size_t i = 0; i < scans.scans.size() && landed == nullptr; ++i) {
        landed = scan(*scans.scans[i]);
    }
    return landed;
}

std::vector<Image::Site> Image::scanAll(const PatternScan& scan) const {
    std::vector<Site> sites;
    visitSites(scan.pattern, [&](uint32_t site) {
        Walk walked = walk(scan, site, true);
        sites.push_back({live_base + site, walked.landed ? live_base + (uintptr_t)*walked.landed : 0, std::move(walked.rejected)});
        return false;
    });
    return sites;
}

std::vector<uintptr_t> Image::findPattern(const Pattern& pattern) const {
    std::vector<uintptr_t> sites;
    visitSites(pattern, [&](uint32_t site) {
        sites.push_back(live_base + site);
        return false;
    });
    return sites;
}

std::optional<std::vector<Image::Change>> Image::findLiveChanges(const void* at, size_t size) const {
    const auto live = (uintptr_t)at;
    const uint8_t* file = has_live && contains(live, size) ? fileBytes((int64_t)(live - live_base), size) : nullptr;
    if (file == nullptr) {
        return std::nullopt;
    }
    const auto rva = (uint32_t)(live - live_base);

    // ---- The bytes the loader would leave there: the file's, with every address in the range relocated
    std::vector<uint8_t> expected(file, file + size);
    const uint64_t delta = (uint64_t)live_base - preferred_base;
    constexpr uint32_t WIDEST = 8;
    auto relocation = std::ranges::lower_bound(relocations, rva >= WIDEST ? rva - WIDEST : 0, {}, &Relocation::rva);
    for (; relocation != relocations.end() && relocation->rva < rva + size; ++relocation) {
        const uint8_t* value_bytes = fileBytes(relocation->rva, relocation->width);
        if (value_bytes != nullptr && relocation->rva + relocation->width > rva) {
            uint64_t value = 0;
            std::memcpy(&value, value_bytes, relocation->width);
            value += delta;
            uint8_t relocated[WIDEST];
            std::memcpy(relocated, &value, sizeof(relocated));
            for (uint32_t i = 0; i < relocation->width; ++i) {
                const int64_t offset = (int64_t)relocation->rva + i - rva;
                if (offset >= 0 && (uint64_t)offset < size) {
                    expected[(size_t)offset] = relocated[i];
                }
            }
        }
    }

    // ---- The runs that differ
    std::vector<Change> changes;
    const auto* bytes = (const uint8_t*)at;
    for (size_t i = 0; i < size; ++i) {
        if (bytes[i] != expected[i]) {
            if (!changes.empty() && changes.back().at + changes.back().size == live + i) {
                ++changes.back().size;
            } else {
                changes.push_back({live + i, 1});
            }
        }
    }
    return changes;
}

bool Image::contains(uintptr_t live, size_t count) const {
    return live >= live_base && live - live_base <= image_size && count <= image_size - (live - live_base);
}

bool Image::isCode(uintptr_t live) const {
    const uintptr_t rva = live - live_base;
    return contains(live) && std::ranges::any_of(sections, [rva](const Section& section) {
               return section.code && rva >= section.rva && rva < (uintptr_t)section.rva + section.virtual_size;
           });
}

} // namespace scanner
