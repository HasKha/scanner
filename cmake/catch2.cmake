include_guard(GLOBAL)
include(FetchContent)

FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.8.1
    GIT_SHALLOW TRUE
)

# Off, Catch's own handler sees a fault before any __except does, and ends the run on one Image::scan() is there to
# catch.
set(CATCH_CONFIG_NO_WINDOWS_SEH ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(catch2)
