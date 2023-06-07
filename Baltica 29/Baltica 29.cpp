// Baltica 29.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include "VMPDetect.h"

int main()
{
    printf("Compare list cpuid ->\t%x\n", vmp_improve::compare_cpuid_list());
    printf("Cpuid check ->\t%x\n", vmp_improve::cpuid_is_hyperv());

    printf("Is single step bad ->\t%x\n", vmp_improve::single_step_check());

    printf("Is smbios bad string ->\t%x\n", vmp_improve::is_smbios_bad()); 
    printf("Is apic bad string ->\t%x\n", vmp_improve::is_acpi_bad());
    printf("Is bad pool tag ->\t%x\n", vmp_improve::is_bad_pool_in_system());

    std::cin.get();
}
