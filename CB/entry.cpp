#include <Windows.h>
#include <conio.h>
#include <intrin.h>

struct CHEAT_BLOCKER
{
	struct CB_X_DATA
	{
		DWORD Data[17];
	};
};

using cb_init = int(__stdcall*)(unsigned int*, struct CHEAT_BLOCKER::CB_X_DATA*);
using cb_xor = void* (*)();

int hk_integrity_buf()
{
	return 1;
}

VOID* detour_create(BYTE* src, CONST BYTE* dst, CONST INT len)
{
	auto jmp = static_cast<BYTE*>(malloc(len + 5));
	DWORD old_protect;
	VirtualProtect(src, len, PAGE_READWRITE, &old_protect);
	memcpy(jmp, src, len);
	jmp += len;
	jmp[0] = 0xE9;
	*reinterpret_cast<DWORD*>(jmp + 1) = static_cast<DWORD>(src + len - jmp) - 5;
	src[0] = 0xE9;
	*reinterpret_cast<DWORD*>(src + 1) = static_cast<DWORD>(dst - src) - 5;
	for (INT i = 5; i < len; i++)
		src[i] = 0x90;
	VirtualProtect(src, len, old_protect, &old_protect);
	return(jmp - len);
}

__declspec(dllexport) int __stdcall _CB_L_(unsigned int* unk, struct CHEAT_BLOCKER::CB_X_DATA* cb_data)
{
	_cprintf("[X] Initialize CB.dll export.\n");
	auto result = 1;
	const auto cb_instance = reinterpret_cast<uintptr_t>(LoadLibraryA("CB.dll"));
	if (cb_instance)
	{
		_cprintf("[X] CB.dll 0x%p .\n", cb_instance);
		const auto cb_object = GetProcAddress(reinterpret_cast<HMODULE>(cb_instance), reinterpret_cast<LPCSTR>(1));
		if (cb_object)
		{
			result = reinterpret_cast<cb_init>(cb_object)(unk, cb_data);
			for (int i = 0; i < 30; i++)
			{
				if (IsBadReadPtr(reinterpret_cast<void*>(cb_data->Data[i]), sizeof(uintptr_t)))
					continue;

				_cprintf("[X] CB_VirtualFunc[%i] : 0x%p .\n", i, cb_data->Data[i]);
			}
			for (int i = 0; i < 7; i++)
			{
				detour_create(reinterpret_cast<PBYTE>(cb_data->Data[i]), reinterpret_cast<PBYTE>(hk_integrity_buf), 5);
			}
		}
	}
	return result;
}

void load_module()
{
	_cprintf("[X] Load CB.dll.\n");
	HMODULE h_lib;
	do
	{
		h_lib = LoadLibraryW(L"CB.dll");
		Sleep(100);
	} while (!h_lib);
	_cprintf("[X] CB.dll Loaded.\n");
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hInst);
		AllocConsole();
		_cprintf("[X] Dll Loaded.\n");
		CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(load_module), nullptr, 0, nullptr);
	}
	return 1;
}