#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <type_traits>
#include <vector>

// What to look for in an executable's code: a byte pattern, and the steps that take a site it matches to the address
// wanted. The grammar and the steps are memtools' (DeltaRaidcore/memtools, MIT), names included, so a signature
// written for memtools is written for this: `PatternScan("48 8D 0D <? ? ? ?>", AdvWcard(), Follow())` reads the same
// in either. The steps are types here, where memtools has functions, and are built the same way.
namespace scanner {

// memtools kept the first 128 bytes of a longer pattern and dropped the rest without a word. Here a longer one is
// malformed, which fails the build of a pattern made at compile time.
inline constexpr size_t MAX_PATTERN_SIZE = 256;
inline constexpr size_t MAX_STEPS = 16;

// Called only while a pattern made at compile time is malformed, which no constant expression may do: the build fails
// on a pattern it could not read, naming this.
inline void patternIsMalformed() {}

struct PatternByte {
    bool wildcard = false;
    uint8_t value = 0;
};

// A pattern as memtools writes it: a byte in hex, `?` or `??` for one that may be anything, and spaces, `<` and `>`
// anywhere, ignored: the brackets mark the bytes that matter, for the reader. A hex digit with none after it is a byte
// of its own, as in memtools. Lowercase is read too, which memtools refused.
class Pattern {
public:
    constexpr Pattern() = default;

    constexpr Pattern(const char* text) {
        for (size_t i = 0; text[i] != '\0' && !malformed; ++i) {
            const char c = text[i];
            if (c == ' ' || c == '<' || c == '>') {
                // Only for the reader.
            } else if (length == MAX_PATTERN_SIZE) {
                malformed = true;
            } else if (c == '?') {
                bytes[length++] = {true, 0};
                i += text[i + 1] == '?' ? 1 : 0;
            } else if (const int high = hexValue(c); high >= 0) {
                const int low = hexValue(text[i + 1]);
                bytes[length++] = {false, (uint8_t)(low >= 0 ? high * 16 + low : high)};
                i += low >= 0 ? 1 : 0;
            } else {
                malformed = true;
            }
        }
        if (malformed) {
            if (std::is_constant_evaluated()) {
                patternIsMalformed();
            }
            length = 0;
        }
    }

    constexpr size_t size() const { return length; }
    // False for text that is not a pattern, or one too long. Such a pattern has no bytes and matches nothing.
    constexpr bool valid() const { return !malformed && length > 0; }
    constexpr const PatternByte& operator[](size_t index) const { return bytes[index]; }

    // Whether the size() bytes from `at` match.
    bool matches(const uint8_t* at) const {
        for (size_t i = 0; i < length; ++i) {
            if (!bytes[i].wildcard && bytes[i].value != at[i]) {
                return false;
            }
        }
        return length > 0;
    }

private:
    static constexpr int hexValue(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        return -1;
    }

    std::array<PatternByte, MAX_PATTERN_SIZE> bytes{};
    size_t length = 0;
    bool malformed = false;
};

// ---- The steps, each from where the last left off. A step that cannot be taken rejects the site, and the scan goes on
// to the next one.

enum class StepKind : uint8_t { Offset, Follow, Strcmp, Wcscmp, CmpI8, CmpI16, CmpI32, CmpI64, PushAddr, PopAddr, AdvWcard, FuncEntry };

struct Step {
    StepKind kind = StepKind::Offset;
    int64_t value = 0;
    const char* text = nullptr;
    const wchar_t* wide_text = nullptr;
};

// Moves by `bytes`, which also moves where AdvWcard() counts from.
struct Offset : Step {
    constexpr explicit Offset(int64_t bytes) : Step{StepKind::Offset, bytes} {}
};

// Reads a rel32 and goes where it points: the end of the four bytes, plus their value. Where it lands need not hold any
// bytes in the file, as a global in zeroed data does not, but must be inside the image.
struct Follow : Step {
    constexpr Follow() : Step{StepKind::Follow} {}
};

// Reads a rel32, and rejects the site unless it points to exactly this text, its terminator included.
struct Strcmp : Step {
    constexpr explicit Strcmp(const char* text) : Step{StepKind::Strcmp, 0, text} {}
};

// Strcmp() for UTF-16 text.
struct Wcscmp : Step {
    constexpr explicit Wcscmp(const wchar_t* text) : Step{StepKind::Wcscmp, 0, nullptr, text} {}
};

// Reject the site unless the 1, 2, 4 or 8 bytes here hold `value`, truncated to that width.
struct CmpI8 : Step {
    constexpr explicit CmpI8(int64_t value) : Step{StepKind::CmpI8, value} {}
};
struct CmpI16 : Step {
    constexpr explicit CmpI16(int64_t value) : Step{StepKind::CmpI16, value} {}
};
struct CmpI32 : Step {
    constexpr explicit CmpI32(int64_t value) : Step{StepKind::CmpI32, value} {}
};
struct CmpI64 : Step {
    constexpr explicit CmpI64(int64_t value) : Step{StepKind::CmpI64, value} {}
};

// Keeps where this is, for PopAddr() to come back to.
struct PushAddr : Step {
    constexpr PushAddr() : Step{StepKind::PushAddr} {}
};
struct PopAddr : Step {
    constexpr PopAddr() : Step{StepKind::PopAddr} {}
};

// Goes to the start of the `sets`th run of wildcards after this point in the pattern, counted from the site's start
// plus every Offset() so far, whatever Follow() did since. A run is wildcards side by side, brackets or not: in
// `8B 0D ? ? ? ? 85 <? ?>`, the second run starts at byte 7. With no run left it stops at the pattern's end. This is
// memtools' walk, kept exactly, so that its signatures land where they did.
struct AdvWcard : Step {
    constexpr explicit AdvWcard(int64_t sets = 1) : Step{StepKind::AdvWcard, sets > 1 ? sets : 1} {}
};

// Goes to the start of the function this is in, by the image's unwind table: x64 only.
struct FuncEntry : Step {
    constexpr FuncEntry() : Step{StepKind::FuncEntry} {}
};

// A pattern and its steps. A site lands when every step can be taken, and they leave it inside the image.
struct PatternScan {
    Pattern pattern;
    std::array<Step, MAX_STEPS> steps{};
    size_t step_count = 0;

    template <typename... Steps>
    constexpr PatternScan(Pattern scan_pattern, Steps... scan_steps)
        : pattern(scan_pattern), steps{static_cast<const Step&>(scan_steps)...}, step_count(sizeof...(Steps)) {
        static_assert(sizeof...(Steps) <= MAX_STEPS, "a PatternScan takes at most MAX_STEPS steps");
        static_assert((std::is_base_of_v<Step, Steps> && ...), "a step is one of scanner's");
    }
};

// Scans tried in turn: the first to land anywhere is the answer. It holds the scans themselves, which must outlive it.
struct FallbackScan {
    std::vector<const PatternScan*> scans;

    FallbackScan(std::initializer_list<std::reference_wrapper<const PatternScan>> tried) {
        for (const PatternScan& scan : tried) {
            scans.push_back(&scan);
        }
    }
};

} // namespace scanner
