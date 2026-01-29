## Overview
This project demonstrates how easy it is to hide private memory by simply hooking hooking `VirtualQuery`.

It achieves that by intercepting every `VirtualQuery` call via either a `Detour Hook`, a `Page Guard Hook` or an `IAT Hook`.
The hook function simply checks if the queried memory region is `MEM_COMMIT` && `MEM_PRIVATE` and Executable and if that is the case it simply returns that the region is `MEM_FREE` and `PAGE_NOACCESS`.

## Usage
In the dllmain.cpp include one of the following 3 headers and build. You can use the TestDll project to test the dll.

- **This will build a dll that uses Microsoft Detours to hook `VirtualQuery`.**
```cpp
#include "variants/detourVariant.hpp"
```

- **This will build a dll that hooks `VirtualQuery` via IAT hooking.**
```cpp
#include "variants/iatVariant.hpp"
```

- **This will build a dll that hooks  `VirtualQuery` via a Page Guard Hook.**
```cpp
#include "variants/pageGuardVariant.hpp"
```
