# scanner

Pattern scans over a Windows x64 executable's file. Scans on a readonly memory copy.

```cpp
#include "scanner/image.h"

constexpr scanner::PatternScan S_Thing("48 8D 0D <? ? ? ?> E8", scanner::AdvWcard(), scanner::Follow());

std::string why;
std::optional<scanner::Image> image = scanner::Image::openRunning(why);
void* thing = image ? image->scan(S_Thing) : nullptr;
```
