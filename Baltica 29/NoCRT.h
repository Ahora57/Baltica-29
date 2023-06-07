#ifndef ENABLE_CRT

#define ENABLE_CRT
 
#include "Struct.h"
#include <cstdint>




namespace NoCRT
{
    namespace mem
    {
        INLINE auto malloc(size_t size) -> PVOID
        {
            return HeapAlloc(RtlProcessHeap(), NULL, size);
        }

        INLINE auto free(PVOID ptr) -> VOID
        {
            if (nullptr != ptr)
                HeapFree(RtlProcessHeap(), NULL, ptr);
        }

        INLINE  auto toupper(INT c) -> INT
        {
            if (c >= 'a' && c <= 'z') return c - 'a' + 'A';
            return c;
        }

        INLINE  auto memcpy(PVOID dest, const PVOID src, uint64_t count) -> PVOID
        {
            auto char_dest = (CHAR*)dest;
            auto char_src = (CHAR*)src;
            if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
            {
                while (count > NULL)
                {
                    *char_dest = *char_src;
                    char_dest++;
                    char_src++;
                    count--;
                }
            }
            else
            {
                char_dest = (CHAR*)dest + count - 1;
                char_src = (CHAR*)src + count - 1;
                while (count > NULL)
                {
                    *char_dest = *char_src;
                    char_dest--;
                    char_src--;
                    count--;
                }
            }
            return dest;
        }
       
        INLINE  auto  memcmp(const PVOID s1, const PVOID s2, uint64_t n) -> INT
        {
            if (n != NULL)
            {
                const uint8_t* p1 = (const uint8_t*)s1, * p2 = (const uint8_t*)s2;
                do
                {
                    if (*p1++ != *p2++) return (*--p1 - *--p2);
                } while (--n != NULL);
            }
            return NULL;
        } 

        INLINE auto memicmp(CONST PVOID s1, CONST PVOID s2, uint64_t n) -> INT
        {
            if (n != NULL)
            {
                const uint8_t* p1 = (uint8_t*)s1, * p2 = (uint8_t*)s2;
                do
                {
                    if (toupper(*p1) != toupper(*p2)) return (*p1 - *p2);
                    p1++;
                    p2++;
                } while (--n != NULL);
            }
            return NULL;
        }
    } 

    namespace str
    {
        INLINE auto strlen(CONST CHAR* string) -> INT
        {
            INT cnt = NULL;
            if (string)
            {
                for (; *string != NULL; ++string) ++cnt;
            }
            return cnt;
        }

    }

}

#endif // !ENABLE_CRT
