#ifndef VMP_IMPROVE

#define VMP_IMPROVE 1
   
#include "NoCRT.h" 
#include "syscall_helper.h"
#include <iostream>


namespace vmp_improve
{

	namespace assembly_code
	{
		EXTERN_C void single_step_cpuid();
		EXTERN_C void single_step_rdtsc();
	}

	namespace util
	{

		INLINE auto is_corrupted_buffer_string(PVOID s_buffer, uint64_t s_size_buffer, CONST CHAR* string, uint64_t str_len) -> bool
		{
			uint64_t buffer = reinterpret_cast<uint64_t>(s_buffer);
			for (size_t i = NULL; i <= s_size_buffer; i++, buffer++)
			{
				if (NoCRT::mem::memicmp(reinterpret_cast<PVOID>(buffer), (PVOID)(string), str_len) == NULL)
						return TRUE;
			}
			return FALSE;
		}

		INLINE  auto get_windows_number() -> INT
		{

			auto NtMajorVersion = *(BYTE*)0x7FFE026C;
			if (NtMajorVersion == 10)
			{
				auto NtBuildNumber = *(INT*)0x7FFE0260;//NtBuildNumber
				if (NtBuildNumber >= 22000)
				{
					return WINDOWS_NUMBER_11;
				}
				return WINDOWS_NUMBER_10;
			}
			else if (NtMajorVersion == 5)
			{
				return WINDOWS_NUMBER_XP;//Windows XP
			}
			else if (NtMajorVersion == 6)
			{
				/*
				https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html
				*/
				switch (*(uint8_t*)0x7FFE0270)  //0x7FFE0270 NtMinorVersion
				{
				case 1:
					return WINDOWS_NUMBER_7;//windows 7
				case 2:
					return WINDOWS_NUMBER_8; //window 8
				case 3:
					return WINDOWS_NUMBER_8_1; //windows 8.1
				default:
					return WINDOWS_NUMBER_11;//windows 11
				}

			}

			return NULL;
		}
		INLINE auto get_number_query_sysytem() -> INT
		{
			auto windows_number = get_windows_number();
			if (windows_number >= WINDOWS_NUMBER_10)
				return 0x36;
			
			else if(windows_number == WINDOWS_NUMBER_8 || windows_number == WINDOWS_NUMBER_8_1)
				return 0x35;
			
			else if (windows_number == WINDOWS_NUMBER_7 || windows_number == WINDOWS_NUMBER_XP)
				return 0x34;
			
			return NULL;
		}

	}

	NO_INLINE auto single_step_check() -> bool
	{ 
		uint8_t byte_step = NULL;
		__try
		{
#ifdef _WIN64
			assembly_code::single_step_cpuid();
#else
			__asm
			{
				pushfd
				or dword ptr[esp], 0x100
				popfd
				cpuid
				nop 
			}
#endif // _WIN64
				 
		}
		__except (byte_step = *(uint8_t*)(GetExceptionInformation())->ExceptionRecord->ExceptionAddress)
		{
			if (byte_step != 0x90) //is exception address opcode is nop?
				return TRUE;
		}
		
		__try
		{

#ifdef _WIN64
			assembly_code::single_step_rdtsc();
#else
			__asm
			{
				pushfd
				or dword ptr[esp], 0x100
				rdtsc
				cpuid
				nop
			}
#endif // _WIN64
		}
		__except (byte_step = *(uint8_t*)(GetExceptionInformation())->ExceptionRecord->ExceptionAddress)
		{
			if (byte_step != 0x90)//is exception address opcode is nop?
				return TRUE;
		}
		return FALSE;
		 
	}
	

	NO_INLINE auto cpuid_is_hyperv() -> bool
	{
		INT cpuid[4];
		__cpuid(cpuid, 1);
		return ((cpuid[2] >> 31) & 1);
	}

	NO_INLINE auto compare_cpuid_list() -> bool
	{

		INT  invalid_list[4];
		INT valid_list[4];
		auto love_colby_list = reinterpret_cast<INT>(L"I_love_colby_<3");//forever <3
		auto valid_leaf = 0x40000000;

		__cpuid(invalid_list, love_colby_list);
		__cpuid(valid_list, valid_leaf);

		if ((invalid_list[0] != valid_list[0]) ||
			(invalid_list[1] != valid_list[1]) ||
			(invalid_list[2] != valid_list[2]) ||
			(invalid_list[3] != valid_list[3]))
			return TRUE;
		return FALSE;
	}

	NO_INLINE auto is_smbios_bad() -> bool
	{

		uint64_t number_bad_string = NULL; 
		ULONG ret_lenght = NULL;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		shell_code_util::shell_code shell_code;
		PSYSTEM_FIRMWARE_TABLE_INFORMATION table_info = NULL;

#ifdef _WIN64
		uint8_t ShellSyscall[] =
		{
			0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscall_number
			0x4C, 0x8B, 0xD1,           // mov r10,rcx
			0x0F, 0x05,                 // syscall
			0xC3                        // ret
		};
#else 
		uint8_t ShellSyscall[] =
		{
			0xB8, 0x0, 0x0, 0x0, 0x0,				// mov eax,syscall_number
			0x64, 0x8B, 0x15, 0xC0, 0x0, 0x0, 0x0,  // mov edx, dword ptr fs : [0x000000C0]
			0xFF, 0xD2,								// call edx via call Wow64Transition
			0xC3									// ret
		};
#endif // _WIN64

		const CHAR* ListCorruptedString[] =
		{
			"VMware",	//VMWare
			"VMW-",
			"RAM socket #",
			"RAM slot #",
			"Welcome to the", //str - Welcome to the Virtual Machine,but we try check 2 string for bypass lazy anti-anti-vm
			"Machine",	//Nanomachine,son!
			"VirtualBox", //VirtualBox
			"Oracle",
			"vboxVer",
			"vboxRev" 
		};

		if (!shell_code.init_shell(ShellSyscall, sizeof(ShellSyscall)))
		{
			printf("Bad init shell!\n");
			return FALSE;
		}
		shell_code.set_syscall(util::get_number_query_sysytem());

		table_info = reinterpret_cast<PSYSTEM_FIRMWARE_TABLE_INFORMATION>(NoCRT::mem::malloc(sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) * 2));

		table_info->ProviderSignature = 'RSMB';
		table_info->TableID = NULL;
		table_info->TableBufferLength = NULL;
		table_info->Action = SystemFirmwareTable_Get;

		nt_status = shell_code.call_shell<NTSTATUS>(SystemFirmwareTableInformation, table_info, sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) * 2, &ret_lenght);
		 
		NoCRT::mem::free(table_info);

		table_info = reinterpret_cast<PSYSTEM_FIRMWARE_TABLE_INFORMATION>(NoCRT::mem::malloc(ret_lenght * 2));
		
		if (table_info && nt_status == STATUS_BUFFER_TOO_SMALL)
		{
			table_info->ProviderSignature = 'RSMB';
			table_info->TableID = NULL;
			table_info->TableBufferLength = ret_lenght;
			table_info->Action = SystemFirmwareTable_Get;

			nt_status = shell_code.call_shell<NTSTATUS>(SystemFirmwareTableInformation, table_info, ret_lenght, &ret_lenght);
			
			for (INT i = NULL; i < sizeof(ListCorruptedString) / sizeof(ListCorruptedString[0]) ; i++)
			{
				if (util::is_corrupted_buffer_string(table_info->TableBuffer, table_info->TableBufferLength, ListCorruptedString[i], NoCRT::str::strlen(ListCorruptedString[i])))
					number_bad_string++;
			}

		}
		NoCRT::mem::free(table_info);
		shell_code.de_init_shell();
		return number_bad_string >= 2;
	
	}

	NO_INLINE auto is_acpi_bad() -> bool
	{

		uint64_t number_bad_string = NULL;
		ULONG ret_lenght = NULL;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		shell_code_util::shell_code shell_code;
		PSYSTEM_FIRMWARE_TABLE_INFORMATION table_info = NULL;

#ifdef _WIN64
		uint8_t ShellSyscall[] =
		{
			0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscall_number
			0x4C, 0x8B, 0xD1,           // mov r10,rcx
			0x0F, 0x05,                 // syscall
			0xC3                        // ret
		};
#else 
		uint8_t ShellSyscall[] =
		{
			0xB8, 0x0, 0x0, 0x0, 0x0,				// mov eax,syscall_number
			0x64, 0x8B, 0x15, 0xC0, 0x0, 0x0, 0x0,  // mov edx, dword ptr fs : [0x000000C0]
			0xFF, 0xD2,								// call edx via call Wow64Transition
			0xC3									// ret
		};
#endif // _WIN64


		const CHAR* ListCorruptedString[] =
		{
			"VMWARE",//VMWare
			"VMware Virtual Battery",
			"VBOX"	//VirtualBox
		};

		if (!shell_code.init_shell(ShellSyscall, sizeof(ShellSyscall)))
		{
			printf("Bad init shell!\n");
			return FALSE;
		}
		shell_code.set_syscall(util::get_number_query_sysytem());

		table_info = reinterpret_cast<PSYSTEM_FIRMWARE_TABLE_INFORMATION>(NoCRT::mem::malloc(sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) * 2));

		table_info->ProviderSignature = 'ACPI';
		table_info->TableID = NULL;
		table_info->TableBufferLength = NULL;
		table_info->Action = SystemFirmwareTable_Get;

		nt_status = shell_code.call_shell<NTSTATUS>(SystemFirmwareTableInformation, table_info, sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) * 2, &ret_lenght);

		NoCRT::mem::free(table_info);

		table_info = reinterpret_cast<PSYSTEM_FIRMWARE_TABLE_INFORMATION>(NoCRT::mem::malloc(ret_lenght * 2));

		if (table_info && nt_status == STATUS_BUFFER_TOO_SMALL)
		{
			table_info->ProviderSignature = 'ACPI';
			table_info->TableID = NULL;
			table_info->TableBufferLength = ret_lenght;
			table_info->Action = SystemFirmwareTable_Get;

			nt_status = shell_code.call_shell<NTSTATUS>(SystemFirmwareTableInformation, table_info, ret_lenght, &ret_lenght);
			
			for (INT i = NULL; i < sizeof(ListCorruptedString) / sizeof(ListCorruptedString[0]); i++)
			{
				if (util::is_corrupted_buffer_string(table_info->TableBuffer, table_info->TableBufferLength, ListCorruptedString[i], NoCRT::str::strlen(ListCorruptedString[i])))
					number_bad_string++;
			}
		}

		NoCRT::mem::free(table_info);
		shell_code.de_init_shell();
		return number_bad_string != NULL;

	}

	NO_INLINE auto is_bad_pool_in_system() -> bool
	{
		PVOID buffer_pool_info = NULL;
		uint64_t bad_pool_number = NULL;
		ULONG ret_lenght = NULL;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		shell_code_util::shell_code shell_code;

#ifdef _WIN64
		uint8_t ShellSyscall[] =
		{
			0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscall_number
			0x4C, 0x8B, 0xD1,           // mov r10,rcx
			0x0F, 0x05,                 // syscall
			0xC3                        // ret
		};
#else 
		uint8_t ShellSyscall[] =
		{
			0xB8, 0x0, 0x0, 0x0, 0x0,				// mov eax,syscall_number
			0x64, 0x8B, 0x15, 0xC0, 0x0, 0x0, 0x0,  // mov edx, dword ptr fs : [0x000000C0]
			0xFF, 0xD2,								// call edx via call Wow64Transition
			0xC3									// ret
		};
#endif // _WIN64

		const CHAR* ListBadPool[] =
		{
			"VM3D",//vm3dmp.sys  VMware
			"vmmp",//vm3dmp.sys
			"CTGC", //vmci.sys
			"HGCC",//vmhgfs.sys
			"HGNM",//vmhgfs.sys
			"VMBL",//vmmemctl.sys
			"VBDM", //VBoxWddm.sys	VirtualBox
			"VBGA",	//VBoxWddm.sys 

		};
		if (!shell_code.init_shell(ShellSyscall, sizeof(ShellSyscall)))
		{
			printf("Bad init shell!\n");
			return FALSE;
		}
		shell_code.set_syscall(util::get_number_query_sysytem());

		nt_status = shell_code.call_shell<NTSTATUS>(SystemPoolTagInformation, buffer_pool_info, ret_lenght, &ret_lenght);

		while (nt_status == STATUS_INFO_LENGTH_MISMATCH) 
		{
			if (buffer_pool_info != NULL)
				NoCRT::mem::free(buffer_pool_info);

			buffer_pool_info = NoCRT::mem::malloc (ret_lenght);
			nt_status = shell_code.call_shell<NTSTATUS>(SystemPoolTagInformation, buffer_pool_info, ret_lenght, &ret_lenght);
		}  

		if (!NT_SUCCESS(nt_status))
		{
			if (buffer_pool_info != NULL)
				NoCRT::mem::free(buffer_pool_info);
			shell_code.de_init_shell();
			return FALSE;
		}

		PSYSTEM_POOLTAG_INFORMATION system_pool_tagInfo = reinterpret_cast<PSYSTEM_POOLTAG_INFORMATION>(buffer_pool_info);
		PSYSTEM_POOLTAG system_pool_tag = reinterpret_cast<PSYSTEM_POOLTAG>(&system_pool_tagInfo->TagInfo->Tag);
		for (ULONG i = NULL; i < system_pool_tagInfo->Count; i++, system_pool_tag++)
		{
			for (size_t i = NULL; i < sizeof(ListBadPool) / sizeof(ListBadPool[0]); i++)
			{
				if (NoCRT::mem::memcmp(reinterpret_cast<CHAR*>(system_pool_tag->Tag), (PVOID)(ListBadPool[i]), 4) == NULL)
					bad_pool_number++;
			}
			
		}
		NoCRT::mem::free(buffer_pool_info);
		shell_code.de_init_shell();
		return bad_pool_number >= 2;
	}

}


#endif // !VMP_IMPROVE