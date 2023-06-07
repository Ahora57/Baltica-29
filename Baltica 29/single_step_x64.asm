.code

single_step_cpuid proc
pushfq
or dword ptr [rsp], 0100h 
popfq
cpuid
nop
ret
single_step_cpuid endp

single_step_rdtsc proc
pushfq
or dword ptr [rsp], 0100h 
popfq
rdtsc
nop
ret
single_step_rdtsc endp
 

end