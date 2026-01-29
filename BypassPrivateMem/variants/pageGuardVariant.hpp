#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace PageGuardHook
{
	inline SIZE_T WINAPI VirtualQueryHook(
		_In_opt_ LPCVOID lpAddress,
		_Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
		_In_ SIZE_T dwLength)
	{
		SIZE_T realVQReturn = VirtualQuery(lpAddress, lpBuffer, dwLength);

		DWORD oldProtect;
		VirtualProtect(VirtualQuery, 1,
			PAGE_EXECUTE_READ | PAGE_GUARD,
			&oldProtect);

		if (realVQReturn)
		{
			if (lpBuffer->State == MEM_COMMIT &&
				lpBuffer->Type == MEM_PRIVATE &&
				lpBuffer->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
					PAGE_EXECUTE_WRITECOPY))
			{
				lpBuffer->State = MEM_FREE;
			}
		}

		return realVQReturn;
	}

	LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS exceptionPointers)
	{
		if (exceptionPointers->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		{
			if (exceptionPointers->ExceptionRecord->ExceptionAddress == reinterpret_cast<PVOID>(VirtualQuery))
			{
				exceptionPointers->ContextRecord->Rip = reinterpret_cast<DWORD64>(VirtualQueryHook);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

	inline void CommitAll()
	{
		AddVectoredExceptionHandler(1, ExceptionHandler);

		DWORD oldProtect;
		VirtualProtect(VirtualQuery, 1,
			PAGE_EXECUTE_READ | PAGE_GUARD,
			&oldProtect);
	}

	inline void DecommitAll()
	{

	}
}

using namespace PageGuardHook;