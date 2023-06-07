#ifndef SYSCALL_HELPER

#define SYSCALL_HELPER 1  
 
#include "NoCRT.h"
namespace shell_code_util
{
	
	class shell_code
	{
	private :
		PVOID shell_address = NULL;
		

	public:
		INLINE auto set_syscall(uint32_t syscall_number)->VOID
		{ 
			NoCRT::mem::memcpy(reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(shell_address)+1 ), &syscall_number, 4); //set syscall
		}


		template<typename ret_status, typename... Args>
		INLINE auto call_shell(Args... args) -> ret_status
		{
			auto fun =  reinterpret_cast<PVOID(*)(Args...)>(shell_address);
			return reinterpret_cast<ret_status>(fun(args...));
		}
		
		INLINE auto init_shell(uint8_t* shell_code = NULL,uint32_t size_shell = NULL) -> bool
		{
			shell_address = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (shell_address == NULL)
				return FALSE;
			if (shell_code && size_shell)
				NoCRT::mem::memcpy(shell_address, shell_code, size_shell);
			return TRUE;
		}
		
		INLINE auto de_init_shell() -> VOID
		{
			if (shell_address)
				VirtualFree(shell_address, NULL, MEM_RELEASE);
		}

	 };
}
#endif // !SYSCALL_HELPER
