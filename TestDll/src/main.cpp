#include <Windows.h>
#include <print>

void FindPrivateMem()
{
	MEMORY_BASIC_INFORMATION mbi;
	uint8_t* currentAddress = nullptr;

	while (VirtualQuery(currentAddress, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_COMMIT &&
			mbi.Type == MEM_PRIVATE &&
			mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
		{
			std::println("Found: {:P}", mbi.BaseAddress);
		}
		currentAddress = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
	}
}

int main()
{
	LPVOID allocMem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	std::println("allocMem: {:P}", allocMem);

	HMODULE hDll = LoadLibraryA("./BypassPrivateMem.dll");
	if (hDll == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	FindPrivateMem();

	FreeLibrary(hDll);

	return 0;
}
