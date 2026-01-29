#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace IatHook
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

	inline bool HookIATEntry(HMODULE hModule, const char* targetDll, const char* targetFunction, PVOID hookFunction,
	                         PVOID* originalFunction)
	{
		auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
			return false;

		IMAGE_DATA_DIRECTORY importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (importDirectory.Size == 0)
			return false;

		auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
			reinterpret_cast<BYTE*>(hModule) + importDirectory.VirtualAddress);

		for (; importDescriptor->Name != 0; importDescriptor++)
		{
			const char* dllName = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(hModule) + importDescriptor->
				Name);

			if (_stricmp(dllName, targetDll) != 0)
				continue;

			auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
				reinterpret_cast<BYTE*>(hModule) + importDescriptor->FirstThunk);
			auto originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
				reinterpret_cast<BYTE*>(hModule) + importDescriptor->OriginalFirstThunk);

			for (; originalThunk->u1.Function != 0; thunk++, originalThunk++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
					continue;

				auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
					reinterpret_cast<BYTE*>(hModule) + originalThunk->u1.AddressOfData);

				if (strcmp(importByName->Name, targetFunction) != 0)
					continue;

				DWORD oldProtect;
				if (!VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect))
					return false;

				if (originalFunction)
					*originalFunction = reinterpret_cast<PVOID>(thunk->u1.Function);

				thunk->u1.Function = reinterpret_cast<ULONG_PTR>(hookFunction);

				VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);

				return true;
			}
		}

		return false;
	}

	inline void CommitAll()
	{
		HMODULE hCurrentModule = GetModuleHandleA(nullptr);
		if (hCurrentModule == nullptr)
			return;

		PVOID originalFunc = nullptr;
		if (HookIATEntry(hCurrentModule, "kernel32.dll", "VirtualQuery",
		                 reinterpret_cast<PVOID>(VirtualQueryHook), &originalFunc))
		{
			if (originalFunc)
				pRealVirtualQuery = reinterpret_cast<decltype(pRealVirtualQuery)>(originalFunc);
		}
	}

	inline void DecommitAll()
	{
		HMODULE hCurrentModule = GetModuleHandleA(nullptr);
		if (hCurrentModule == nullptr)
			return;

		HookIATEntry(hCurrentModule, "kernel32.dll", "VirtualQuery",
		             reinterpret_cast<PVOID>(pRealVirtualQuery), nullptr);
	}
}

using namespace IatHook;
