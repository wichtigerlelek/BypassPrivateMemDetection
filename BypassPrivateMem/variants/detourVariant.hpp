#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Detours/detours.h>

namespace DetourHook
{
	static auto pRealVirtualQuery = VirtualQuery;

	inline SIZE_T WINAPI VirtualQueryHook(
		_In_opt_ LPCVOID lpAddress,
		_Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
		_In_ SIZE_T dwLength)
	{
		if (pRealVirtualQuery(lpAddress, lpBuffer, dwLength))
		{
			if (lpBuffer->State == MEM_COMMIT &&
				lpBuffer->Type == MEM_PRIVATE &&
				lpBuffer->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
					PAGE_EXECUTE_WRITECOPY))
			{
				lpBuffer->State = MEM_FREE;
				lpBuffer->Protect = PAGE_NOACCESS;
				return sizeof(MEMORY_BASIC_INFORMATION);
			}
		}
		return pRealVirtualQuery(lpAddress, lpBuffer, dwLength);
	}

	inline void CommitAll()
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&reinterpret_cast<PVOID&>(pRealVirtualQuery), VirtualQueryHook);
		DetourTransactionCommit();
	}

	inline void DecommitAll()
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&reinterpret_cast<PVOID&>(pRealVirtualQuery), VirtualQueryHook);
		DetourTransactionCommit();
	}
}

using namespace DetourHook;