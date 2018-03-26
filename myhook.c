#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>  
#include <sys/mman.h>
#include <errno.h>

int scan_my_range(void* punk_struct);

//Test
#define STR_SEPARATOR "\n"
#define MAX_CHAR_PER_LINE 232
#define MAX_NUMBER_RANGE 10000
#define MAX_SIZE_READ 1000
#define __int64 long long

int g_bReady = 0;


typedef int (*STRCASECMP)(const char*,const char*);
int mem_protect_open( char* start_addr , int len)
{
   unsigned int pagesize = 0;
   pagesize=getpagesize();
   char* ptr=(unsigned char *)((long)start_addr&(~(pagesize-1)));

   return mprotect( ptr ,pagesize , PROT_READ|PROT_WRITE|PROT_EXEC);
}

int mem_protect_close( char* start_addr , int len)
{
   unsigned int pagesize = 0;
   pagesize=getpagesize();
   char* ptr=(unsigned char *)((long)start_addr&(~(pagesize-1)));

   return mprotect( ptr ,pagesize , PROT_READ | PROT_EXEC);
}

int scan_my_range(void* punk_struct)
{
    int ret = 0,j=0;
    return ret;
}


__attribute__ ((noinline ))void jmp_my_code()
{
	__asm__ __volatile__(    
				 "HDS:\n\t"
				 "movq 0x260(%rsp),%rax;\n\t"
				 "cmp 0x268(%rsp),%rax;\n\t"
				 "push %rax;\n\t"
				 "push %rcx;\n\t"
				 "push %rdx;\n\t"
				 "push %rbx;\n\t"
				 "push %rbp;\n\t"
			     "push %rsi;\n\t"
			     "push %rdi;\n\t"
				 "jz  FATD;\n\t"
				 "nop;\n\t"
				 "nop;\n\t"
				 "nop;\n\t"
				 "nop;\n\t"
				 "movq %rsp,%rdi");
	scan_my_range(0);
	__asm__ __volatile__(    
				 "test %eax,%eax;\n\t"
				 "jz  FATD;\n\t"
				 "RIGHT:\n\t"
				 "pop %rdi;\n\t"
			     "pop %rsi;\n\t"
				 "pop %rbp;\n\t"
				 "pop %rbx;\n\t"
				 "pop %rdx;\n\t"
				 "pop %rcx;\n\t"
				 "pop %rax;\n\t"
				 "jmpq *0x00000000\n\t"
				 "FATD:\n\t"
			         "pop %rdi;\n\t"
			         "pop %rsi;\n\t"
				 "pop %rbp;\n\t"
				 "pop %rbx;\n\t"
				 "pop %rdx;\n\t"
				 "pop %rcx;\n\t"
				 "pop %rax;\n\t"
				"jmpq *0x00000000\n\t");
}


int Mystrcasecmp (const char *s1,const char *s2)
{
    static void *handle = NULL;
    static STRCASECMP old_strcasecmp = NULL;
    if (!handle)
    {
        handle = dlopen ("libc.so.6",RTLD_LAZY);
        old_strcasecmp = (STRCASECMP)dlsym (handle,"strcasecmp");
    }
    return old_strcasecmp (s1,s2);
}


int write_code()
{
	int ret = 0;
	char * hook_addr = (char *)0x0000000000;
	char *pChTest = (char*)hook_addr;
	char hook_buf[22] = {0x0};
	memcpy (hook_buf, hook_addr , sizeof (hook_buf)/sizeof (hook_buf[0]));

	unsigned char data[22] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	char jmpCode[] = "\xFF\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

	if( 0 == memcmp(data,hook_buf,22) )
	{
		if( -1 != mem_protect_open(hook_addr,1024) )
		{
			//修改
			*(__int64*)(&jmpCode[6]) = (__int64)(__int64*)jmp_my_code;
			memcpy(pChTest,jmpCode,14 );
			ret = 1;
		}
		else{
			printf("fuck.. %s\n",strerror(errno));
		}

	}
	
	return ret;
}

int strcasecmp (const char *pszSrc,const char *pszDest)
{
    int nRet = -1,nCnt = 0;
    char *pszGot = NULL,szBuf[MAX_CHAR_PER_LINE] = {0},szBuf_agent[MAX_CHAR_PER_LINE*2] = {0};
    FILE *pFile = NULL;
	FILE *pFile_Aget = NULL;
    if (!g_bReady)
    {
		if( 1 == write_code() )
			g_bReady = 1;
    }
    return Mystrcasecmp (pszSrc,pszDest);
}
