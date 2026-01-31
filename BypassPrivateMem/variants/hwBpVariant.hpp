#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

namespace HwBpHook
{
	inline bool SetLocalHwBp(HANDLE hThread, DWORD64 address, int regIdx)
	{
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (!GetThreadContext(hThread, &ctx))
			return false;

		(&ctx.Dr0)[regIdx] = address;

		const int enableBit = regIdx * 2;
		const int condBit = 16 + (regIdx * 4);

		ctx.Dr7 &= ~(1ULL << enableBit);
		ctx.Dr7 &= ~(0xFULL << condBit);
		ctx.Dr7 |= (1ULL << enableBit);

		return SetThreadContext(hThread, &ctx);
	}

	inline bool SetGlobalHwBp(DWORD64 address, int regIdx)
	{
		DWORD currentThreadId = GetCurrentThreadId();
		DWORD currentProcessId = GetCurrentProcessId();

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			return false;

		THREADENTRY32 te32 = {};
		te32.dwSize = sizeof(THREADENTRY32);

		if (!Thread32First(hSnapshot, &te32))
		{
			CloseHandle(hSnapshot);
			return false;
		}

		bool success = true;
		do
		{
			if (te32.th32OwnerProcessID == currentProcessId)
			{
				HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
				                            THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
				if (hThread)
				{
					if (te32.th32ThreadID != currentThreadId)
						SuspendThread(hThread);

					if (!SetLocalHwBp(hThread, address, regIdx))
						success = false;

					if (te32.th32ThreadID != currentThreadId)
						ResumeThread(hThread);

					CloseHandle(hThread);
				}
			}
		}
		while (Thread32Next(hSnapshot, &te32));

		CloseHandle(hSnapshot);
		return success;
	}

	inline SIZE_T WINAPI VirtualQueryHook(
		_In_opt_ LPCVOID lpAddress,
		_Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
		_In_ SIZE_T dwLength)
	{
		SIZE_T realVQReturn = VirtualQuery(lpAddress, lpBuffer, dwLength);

		SetLocalHwBp(GetCurrentThread(), reinterpret_cast<DWORD64>(VirtualQuery), 0);

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

	inline LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS exceptionPointers)
	{
		if (exceptionPointers->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		{
			if (exceptionPointers->ContextRecord->Dr6 & 1)
			{
				if (exceptionPointers->ExceptionRecord->ExceptionAddress ==
					reinterpret_cast<PVOID>(VirtualQuery))
				{
					exceptionPointers->ContextRecord->Rip =
						reinterpret_cast<DWORD64>(VirtualQueryHook);
					exceptionPointers->ContextRecord->Dr6 &= ~1ULL;
					exceptionPointers->ContextRecord->Dr7 &= ~1ULL;
					exceptionPointers->ContextRecord->EFlags |= (1 << 16);

					return EXCEPTION_CONTINUE_EXECUTION;
				}
			}
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	inline void CommitAll()
	{
		AddVectoredExceptionHandler(1, ExceptionHandler);
		SetGlobalHwBp(reinterpret_cast<DWORD64>(VirtualQuery), 0);
	}

	inline void DecommitAll()
	{
	}
}

using namespace HwBpHook;
