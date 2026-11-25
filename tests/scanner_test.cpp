#include <windows.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "scanner/image.h"

using namespace scanner;

namespace {

// ---- A small x64 executable, written byte by byte, whose every site is known.
//
//   .text   0x1000  LEA RCX,["other text"]; CALL 0x1040; MOV EAX,[0x3800]; RET          one function, in the unwind table
//           0x1040  SUB RSP,28; MOV EAX,0x12345678; LEA RDX,[L"wide"]; ADD RSP,28; RET  another
//           0x1080  LEA RCX,["hello assert"]; CALL 0x1040; NOP; NOP; RET                in no function the table knows
//           0x10A0  JMP outside the image
//   .rdata  0x2010  "hello assert"   0x2030 "other text"   0x2040 L"wide"   0x2080 the address of 0x1040, relocated
//   .data   0x3000  0x200 bytes in the file, 0x1000 in the image: 0x3800 is zeroes the file does not hold
//   .pdata  0x4000, .reloc 0x5000

constexpr uint64_t IMAGE_BASE = 0x140000000;
constexpr uint32_t IMAGE_SIZE = 0x6000;
constexpr uint32_t HEADERS_SIZE = 0x400;
constexpr uint32_t RAW_SECTION_SIZE = 0x200;

struct SectionSpec {
    const char* name;
    uint32_t rva;
    uint32_t virtual_size;
    uint32_t characteristics;
};
constexpr SectionSpec SECTIONS[] = {
    {".text", 0x1000, RAW_SECTION_SIZE, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ},
    {".rdata", 0x2000, RAW_SECTION_SIZE, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ},
    {".data", 0x3000, 0x1000, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE},
    {".pdata", 0x4000, 0x18, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ},
    {".reloc", 0x5000, 0x0C, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ},
};
constexpr uint32_t SECTION_COUNT = sizeof(SECTIONS) / sizeof(SECTIONS[0]);

uint32_t fileOffsetOf(uint32_t rva) {
    uint32_t offset = 0;
    for (uint32_t i = 0; i < SECTION_COUNT; ++i) {
        if (rva >= SECTIONS[i].rva && rva < SECTIONS[i].rva + RAW_SECTION_SIZE) {
            offset = HEADERS_SIZE + i * RAW_SECTION_SIZE + (rva - SECTIONS[i].rva);
        }
    }
    REQUIRE(offset != 0);
    return offset;
}

class ExeWriter {
public:
    std::vector<uint8_t> bytes = std::vector<uint8_t>(HEADERS_SIZE + SECTION_COUNT * RAW_SECTION_SIZE);

    void put(uint32_t rva, std::initializer_list<uint8_t> code) { std::memcpy(&bytes[fileOffsetOf(rva)], code.begin(), code.size()); }
    void putRaw(uint32_t rva, const void* data, size_t size) { std::memcpy(&bytes[fileOffsetOf(rva)], data, size); }
    // A rel32 at `rva` to `target`.
    void putRel32(uint32_t rva, uint32_t target) {
        const int32_t displacement = (int32_t)(target - (rva + 4));
        putRaw(rva, &displacement, sizeof(displacement));
    }
};

std::vector<uint8_t> buildExe() {
    ExeWriter exe;

    // ---- Headers
    auto* dos = (IMAGE_DOS_HEADER*)exe.bytes.data();
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;
    auto* nt = (IMAGE_NT_HEADERS64*)(exe.bytes.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = SECTION_COUNT;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.ImageBase = IMAGE_BASE;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = RAW_SECTION_SIZE;
    nt->OptionalHeader.SizeOfImage = IMAGE_SIZE;
    nt->OptionalHeader.SizeOfHeaders = HEADERS_SIZE;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {0x4000, 0x18};
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x5000, 0x0C};
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (uint32_t i = 0; i < SECTION_COUNT; ++i, ++section) {
        std::memcpy(section->Name, SECTIONS[i].name, std::strlen(SECTIONS[i].name));
        section->VirtualAddress = SECTIONS[i].rva;
        section->Misc.VirtualSize = SECTIONS[i].virtual_size;
        section->PointerToRawData = HEADERS_SIZE + i * RAW_SECTION_SIZE;
        section->SizeOfRawData = RAW_SECTION_SIZE;
        section->Characteristics = SECTIONS[i].characteristics;
    }

    // ---- .text
    exe.put(0x1000, {0x48, 0x8D, 0x0D});
    exe.putRel32(0x1003, 0x2030);
    exe.put(0x1007, {0xE8});
    exe.putRel32(0x1008, 0x1040);
    exe.put(0x100C, {0x8B, 0x05});
    exe.putRel32(0x100E, 0x3800);
    exe.put(0x1012, {0xC3});

    exe.put(0x1040, {0x48, 0x83, 0xEC, 0x28, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x48, 0x8D, 0x15});
    exe.putRel32(0x104C, 0x2040);
    exe.put(0x1050, {0x48, 0x83, 0xC4, 0x28, 0xC3});

    exe.put(0x1080, {0x48, 0x8D, 0x0D});
    exe.putRel32(0x1083, 0x2010);
    exe.put(0x1087, {0xE8});
    exe.putRel32(0x1088, 0x1040);
    exe.put(0x108C, {0x90, 0x90, 0xC3});

    exe.put(0x10A0, {0xE9});
    exe.putRel32(0x10A1, 0x10000);

    // ---- .rdata
    exe.putRaw(0x2010, "hello assert", sizeof("hello assert"));
    exe.putRaw(0x2030, "other text", sizeof("other text"));
    exe.putRaw(0x2040, L"wide", sizeof(L"wide"));
    const uint64_t function_address = IMAGE_BASE + 0x1040;
    exe.putRaw(0x2080, &function_address, sizeof(function_address));

    // ---- .pdata and .reloc
    const uint32_t functions[] = {0x1000, 0x1013, 0x2100, 0x1040, 0x1055, 0x2100};
    exe.putRaw(0x4000, functions, sizeof(functions));
    const IMAGE_BASE_RELOCATION block{0x2000, 0x0C};
    const WORD entries[] = {(WORD)(IMAGE_REL_BASED_DIR64 << 12 | 0x080), IMAGE_REL_BASED_ABSOLUTE};
    exe.putRaw(0x5000, &block, sizeof(block));
    exe.putRaw(0x5008, entries, sizeof(entries));
    return exe.bytes;
}

const std::filesystem::path& exePath() {
    static const std::filesystem::path path = [] {
        const std::filesystem::path written = std::filesystem::temp_directory_path() / "scanner_test_image.exe";
        const std::vector<uint8_t> bytes = buildExe();
        std::ofstream(written, std::ios::binary).write((const char*)bytes.data(), (std::streamsize)bytes.size());
        return written;
    }();
    return path;
}

Image openExe() {
    std::string why;
    std::optional<Image> image = Image::openFile(exePath(), why);
    INFO(why);
    REQUIRE(image.has_value());
    return std::move(*image);
}

uintptr_t at(uint32_t rva) { return (uintptr_t)(IMAGE_BASE + rva); }

// Never called: only its bytes are looked for.
__declspec(noinline) int distinctiveFunction(int value) { return value * 0x5EED + 0x0DDBA11; }

} // namespace

TEST_CASE("a pattern reads its text") {
    constexpr Pattern PATTERN("48 ?? <? 8b> F 0a");
    static_assert(PATTERN.size() == 6 && PATTERN.valid());
    static_assert(!PATTERN[0].wildcard && PATTERN[0].value == 0x48);
    static_assert(PATTERN[1].wildcard && PATTERN[2].wildcard);
    static_assert(PATTERN[3].value == 0x8B && PATTERN[4].value == 0x0F && PATTERN[5].value == 0x0A);

    const std::string not_hex = "48 XZ";
    CHECK_FALSE(Pattern(not_hex.c_str()).valid());
    std::string too_long;
    for (size_t i = 0; i <= MAX_PATTERN_SIZE; ++i) {
        too_long += "00 ";
    }
    CHECK_FALSE(Pattern(too_long.c_str()).valid());
    CHECK_FALSE(Pattern("").valid());
}

TEST_CASE("a scan lands where its steps take it") {
    const Image image = openExe();

    SECTION("the pattern alone") {
        CHECK(image.findPattern("48 8D 0D ? ? ? ? E8") == std::vector<uintptr_t>{at(0x1000), at(0x1080)});
        CHECK(image.findPattern("0F 0B").empty());
    }
    SECTION("the lowest site whose steps all pass") {
        const PatternScan scan("48 8D 0D <? ? ? ?> E8", AdvWcard(), Strcmp("hello assert"));
        CHECK(image.scan(scan) == (void*)at(0x1083));
        const std::vector<Image::Site> sites = image.scanAll(scan);
        REQUIRE(sites.size() == 2);
        CHECK(sites[0].landed == 0);
        CHECK(sites[0].rejected.find("does not name \"hello assert\"") != std::string::npos);
        CHECK(sites[1].landed == at(0x1083));
    }
    SECTION("wildcard runs, followed") {
        CHECK(image.scan(PatternScan("48 8D 0D <? ? ? ?> E8 <? ? ? ?>", AdvWcard(2), Follow())) == (void*)at(0x1040));
        // With no run left, the pattern's end.
        CHECK(image.scan(PatternScan("B8 78 56 34 12", AdvWcard())) == (void*)at(0x1049));
    }
    SECTION("an address kept and come back to") {
        const PatternScan scan("48 8D 0D <? ? ? ?> E8 <? ? ? ?>", PushAddr(), AdvWcard(), Strcmp("hello assert"), PopAddr());
        CHECK(image.scan(scan) == (void*)at(0x1080));
        CHECK(image.scan(PatternScan("48 8D 0D", PopAddr())) == nullptr);
    }
    SECTION("a global in zeroes the file does not hold") {
        CHECK(image.scan(PatternScan("8B 05 ? ? ? ? C3", Offset(2), Follow())) == (void*)at(0x3800));
    }
    SECTION("compares") {
        CHECK(image.scan(PatternScan("B8 ? ? ? ? 48 8D 15", Offset(1), CmpI32(0x12345678))) == (void*)at(0x1045));
        CHECK(image.scan(PatternScan("B8 ? ? ? ? 48 8D 15", Offset(1), CmpI32(0x12345679))) == nullptr);
        CHECK(image.scan(PatternScan("B8 ? ? ? ? 48 8D 15", Offset(1), CmpI16(0x5678))) == (void*)at(0x1045));
        CHECK(image.scan(PatternScan("B8 ? ? ? ? 48 8D 15", Offset(4), CmpI8(0x12))) == (void*)at(0x1048));
        CHECK(image.scan(PatternScan("48 8D 15 <? ? ? ?>", AdvWcard(), Wcscmp(L"wide"))) == (void*)at(0x104C));
        CHECK(image.scan(PatternScan("48 8D 15 <? ? ? ?>", AdvWcard(), Wcscmp(L"wid"))) == nullptr);
    }
    SECTION("a read outside the file rejects the site, never faults") {
        // Before 0x1000 is no section; before 0x1080, the zeroes between the functions.
        const PatternScan scan("48 8D 0D", Offset(-1), CmpI8(0));
        const std::vector<Image::Site> sites = image.scanAll(scan);
        REQUIRE(sites.size() == 2);
        CHECK(sites[0].rejected.find("is not in the file") != std::string::npos);
        CHECK(image.scan(scan) == (void*)at(0x107F));

        const std::vector<Image::Site> jumps = image.scanAll(PatternScan("E9 ? ? ? ?", Offset(1), Follow()));
        REQUIRE(jumps.size() == 1);
        CHECK(jumps[0].rejected.find("points outside the image") != std::string::npos);
    }
    SECTION("steps that leave the image land nowhere") {
        // From 0x1000 and 0x1080: past the image's end, and before its start.
        CHECK(image.scan(PatternScan("48 8D 0D", Offset(IMAGE_SIZE))) == nullptr);
        const std::vector<Image::Site> sites = image.scanAll(PatternScan("48 8D 0D", Offset(-0x1001)));
        REQUIRE(sites.size() == 2);
        CHECK(sites[0].rejected.find("outside the image") != std::string::npos);
        CHECK(sites[1].landed == at(0x7F));
    }
    SECTION("the function a site is in") {
        CHECK(image.scan(PatternScan("B8 78 56 34 12", FuncEntry())) == (void*)at(0x1040));
        CHECK(image.scan(PatternScan("90 90 C3", FuncEntry())) == nullptr);
    }
    SECTION("fallbacks, in turn") {
        const PatternScan missing("0F 0B");
        const PatternScan found("48 83 EC 28");
        CHECK(image.scan(FallbackScan{missing, found}) == (void*)at(0x1040));
        CHECK(image.scan(FallbackScan{missing}) == nullptr);
    }
    SECTION("nothing for a pattern that is not one") {
        const std::string not_hex = "48 G";
        CHECK(image.scan(PatternScan(not_hex.c_str())) == nullptr);
    }
    SECTION("where things are") {
        CHECK(image.headers().rva == 0);
        CHECK(image.headers().file_size == HEADERS_SIZE);
        REQUIRE(image.sections().size() == SECTION_COUNT);
        CHECK(image.sections()[0].code);
        CHECK_FALSE(image.sections()[0].writable);
        CHECK(image.sections()[2].writable);
        // .data: the image holds more of it than the file.
        CHECK(image.sections()[2].virtual_size == 0x1000);
        CHECK(image.sections()[2].file_size == RAW_SECTION_SIZE);
        CHECK(image.isCode(at(0x1040)));
        CHECK_FALSE(image.isCode(at(0x2010)));
        CHECK(image.contains(at(0x5FFF)));
        CHECK_FALSE(image.contains(at(0x5FFF), 2));
        CHECK(image.preferredAddress(at(0x1234)) == IMAGE_BASE + 0x1234);
    }
}

TEST_CASE("the running executable is its own file") {
    std::string why;
    const std::optional<Image> image = Image::openRunning(why);
    INFO(why);
    REQUIRE(image.has_value());
    CHECK(image->liveBase() == (uintptr_t)GetModuleHandleW(nullptr));

    // A function's bytes, found where it is.
    const auto* function = (const uint8_t*)&distinctiveFunction;
    std::string text;
    constexpr size_t BYTES_LOOKED_FOR = 24;
    for (size_t i = 0; i < BYTES_LOOKED_FOR; ++i) {
        char byte[4];
        std::snprintf(byte, sizeof(byte), "%02X ", function[i]);
        text += byte;
    }
    const std::vector<uintptr_t> sites = image->findPattern(text.c_str());
    CHECK(std::ranges::find(sites, (uintptr_t)function) != sites.end());
    CHECK(image->isCode((uintptr_t)function));

    // Opened once, by whichever call comes first.
    std::string running_why;
    const Image* running = Image::running(&running_why);
    INFO(running_why);
    REQUIRE(running != nullptr);
    CHECK(running == Image::running());
    CHECK(running->liveBase() == image->liveBase());
}
