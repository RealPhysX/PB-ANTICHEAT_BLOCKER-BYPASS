#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

class inject
{
public:
	static int get_proc_id(const std::string& p_name);
	static bool inject_dll(const int& pid, const std::string& dll_path);
	static std::string dll_path(const std::string dll_name);
};

int inject::get_proc_id(const std::string& p_name)
{
	const HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 n_snap = { 0 };

	n_snap.dwSize = sizeof(PROCESSENTRY32);

	if (snap_shot == INVALID_HANDLE_VALUE)return 0;
	if (Process32First(snap_shot, &n_snap) == FALSE)return 0;

	while (Process32Next(snap_shot, &n_snap))
	{
		if (!strcmp(n_snap.szExeFile, p_name.c_str()))
		{
			CloseHandle(snap_shot);
			std::cout << "[+]Process Name : " << p_name << "\n[+]Process ID: " << n_snap.th32ProcessID << std::endl;
			return n_snap.th32ProcessID;
		}
	}
	CloseHandle(snap_shot);
	std::cerr << "[!]Unable to find Process ID" << std::endl;
	return 0;
}

bool inject::inject_dll(const int& pid, const std::string& dll_path)
{
	const long dll_size = dll_path.length() + 1;
	const HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (h_proc == nullptr)
	{
		std::cerr << "[!]Fail to open target process!" << std::endl;
		return false;
	}
	std::cout << "[+]Opening Target Process..." << std::endl;

	const LPVOID my_alloc = VirtualAllocEx(h_proc, nullptr, dll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (my_alloc == nullptr)
	{
		std::cerr << "[!]Fail to allocate memory in Target Process." << std::endl;
		return false;
	}

	std::cout << "[+]Allocating memory in Target Process." << std::endl;
	const int is_write_ok = WriteProcessMemory(h_proc, my_alloc, dll_path.c_str(), dll_size, 0);
	if (is_write_ok == 0)
	{
		std::cerr << "[!]Fail to write in Target Process memory." << std::endl;
		return false;
	}
	std::cout << "[+]Creating Remote Thread in Target Process" << std::endl;

	DWORD d_word;
	const auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(
		LoadLibrary("kernel32"), "LoadLibraryA"));
	const HANDLE h_thread = CreateRemoteThread(h_proc, nullptr, 0, load_library, my_alloc, 0, &d_word);
	if (h_thread == nullptr)
	{
		std::cerr << "[!]Fail to Create Remote Thread" << std::endl;
		return false;
	}

	if ((h_proc != nullptr) && (my_alloc != nullptr) && (is_write_ok != ERROR_INVALID_HANDLE) && (h_thread != nullptr))
	{
		std::cout << "[+]Successfully Injected." << std::endl;
		return true;
	}

	return false;
}

std::string inject::dll_path(const std::string dll_name)
{
	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileName(nullptr, buffer, MAX_PATH);
	const std::wstring::size_type pos = std::string(buffer).find_last_of("\\/");
	return std::string(buffer).substr(0, pos) + std::string("\\") + dll_name;
}

int main(int argc, char* argv[])
{
	char buff[1024];
	sprintf(buff, "%s %s", argv[3], argv[4]);
	ShellExecuteA(nullptr, "open", argv[2], buff, nullptr, SW_RESTORE);

	const auto pid = inject::get_proc_id("PointBlank.exe");
	printf("pid : %i\n", pid);

	return inject::inject_dll(pid, inject::dll_path("CB.dll"));
}