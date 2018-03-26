#在x64下，利用LD_PRELOAD动态连接，给软件增加自己需要的功能#

# 描述：#

> 有一个以前用的软件，一直在用，非常稳定，现在由于业务需要，在显示结果后面，根据配置文件，在进行一次正则过滤。
> 
给原来开发软件的公司打电话，打不通了。。。大家可以发挥想象力！，总之就是没人管了。

# 技术选型：#
> 只是很小的改动，在重新开发一套，时间不允许，而且重新开发的也不一定稳定。所以最后决定在原文件上进行修改，这样时间最短，成本最低。
		
##可行性方案：##

> 1. 在原来的文件上进行二进制修改，考虑到汇编语言开发效率太低，不可取。【放弃】
2. 修改原程序，在合适的地方，使用懒加载方式，调用自己写的so文件，然后在so文件中实现功能。【可以实现，但既要修改原文件，还要写so文件，可以当做备选方案】
3. 不修改原程序，LD_PRELOAD动态连接.so函数劫持，然后对需要进行修改的关键点进行补丁。【不修改原文件，只是利用so文件，进行补丁，新功能在so文件中完成，此方案可以考虑】
				
#任务开始：#

## 运行环境:##

	[root@centos ~]# uname -a
	Linux centos 2.6.32-431.29.2.el6.x86_64 #1 SMP Tue Sep 9 21:36:05 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux

	[root@centos ~]# lsb_release -a
	LSB Version:    :base-4.0-amd64:base-4.0-noarch:core-4.0-amd64:core-4.0-noarch:graphics-4.0-amd64:graphics-4.0-noarch:printing-4.0-amd64:printing-4.0-noarch
	Distributor ID: CentOS
	Description:    CentOS release 6.4 (Final)
	Release:        6.4
	Codename:       Final

##关键点分析：##
升级关键点分析：


	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       mov     rdi, rbp        ; s1
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       mov     esi, offset aVer3 ; "Ver3.0"
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       lea     rbp, [rbx+40h]
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       call    _strcasecmp    ====》我们就来欺骗这个函数
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       test    eax, eax
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       jz      short goto_upgrade


解密算法关键点分析：

	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       mov     [rsp+338h+var_330], esi
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       mov     qword ptr [rsp+338h+var_338], rax ; int
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       mov     rsi, rbp        ; char *
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       call    decode_data ; 	 解密字符串
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                 	   mov     rax, [rsp+338h+var_D8] ==>我patch的是这个地方
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       cmp     [rsp+268h], rax ; rax=解密后的字符串
	.text:XXXXXXXXXXXXXXXX 0F 84 44 02 00 00                       jz      loc_452910

##选定方案:##

> 使用ida分析文件后发现原程序启动后会调用系统的**strcasecmp**函数,来比较版本号进行升级。
好，那么我们就模拟系统libc.so.6文件中的strcasecmp,决定使用【方案3】。

##流程图：##
要写东西，总要先画个流程图吧，这样不至于偏离目标。

---

**下图是原来程序的运行流程图：**

> 程序运行后，会先调用比较函数比较版本号，然后就是一些内部的黑盒逻辑处理了，（由于一些原因，不便透露程序名称，所以隐去了，请大家谅解）如果解密成功，就会把解密出来的内容显示在屏幕上。

![](http://fs-image.pull.net.cn/18-3-18/55487415.jpg)

---

**下图是【方案3】实现的流程图：**

> 我们使用LD_PRELOAD=myhook.so 原文件名称，提前加载so文件，当原程序准备比较版本的时候，这时就会调用红色框中的流程，这个流程中，我们做了二件事，第一读取配置文件，第二，修改原文件中关键点在解密成功后，在加一层判断代码，把这个代码指向我们so文件中的函数，也就是下图的蓝色框内部分。其他部分同上。


![](http://fs-image.pull.net.cn/18-3-18/85455685.jpg)

---



##strcmpcase替换：##

	//懒加载方式，调用真正的strcasecmp函数
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

	//软件会调用我的这个函数
	int strcasecmp (const char *pszSrc,const char *pszDest)
	{
		loadconfig();	//这里我用来加载我自己的配置文件
		write_code();   //用来patch功能的代码
	    return Mystrcasecmp (pszSrc,pszDest);
	}

##读取配置文件：##

	void loadconfig()
	{
		if (pFile = fopen ("/root/conf.txt","rt"))
        {
			。。。。。   //按自己的规则加载配置文件

            fclose (pFile);
            pFile = NULL;
       
			g_bReady = 1;		//只加载一次
        }
	}


##编写正则表达式过滤代码：##

	int myRegularcheck(const char* decode_str)
	{
		//根据配置文件，开始做事
	}


###编写原文件和so文件之间的HOOK代码：##

	__asm__ __volatile__( 
				 ***"movq 0x260(%rsp),%rax;\n\t"
				 ***"cmp 0x268(%rsp),%rax;\n\t"
				 "push %rax;\n\t"		===>保存现场
				 "push %rcx;\n\t"		===>保存现场
				 "push %rdx;\n\t"		===>保存现场
				 "push %rbx;\n\t"		===>保存现场
				 "push %rbp;\n\t"		===>保存现场
			     "push %rsi;\n\t"		===>保存现场
			     "push %rdi;\n\t"		===>保存现场
				 ***"jz  FATD;\n\t"		===>保存现场
				 ***"movq %rsp,%rdi"		 ===>解密后的字符串
				 ***"call *myRegularcheck"	 ===>正则表达试过滤
				 ***"test %eax,%eax;\n\t"  ===>比对失败
				 ***"jz  FATD;\n\t"
			     "pop %rdi;\n\t"		===>恢复现场
			     "pop %rsi;\n\t"		===>恢复现场
				 "pop %rbp;\n\t"		===>恢复现场
				 "pop %rbx;\n\t"		===>恢复现场
				 "pop %rdx;\n\t"		===>恢复现场
				 "pop %rcx;\n\t"		===>恢复现场
				 "pop %rax;\n\t"		===>恢复现场
				 ***"jmpq *0x00000000\n\t"	==>显示字符串
				 ***"FATD:\n\t"
			     "pop %rdi;\n\t"		===>恢复现场
			     "pop %rsi;\n\t"		===>恢复现场
				 "pop %rbp;\n\t"		===>恢复现场
				 "pop %rbx;\n\t"		===>恢复现场
				 "pop %rdx;\n\t"		===>恢复现场
				 "pop %rcx;\n\t"		===>恢复现场
				 "pop %rax;\n\t"		===>恢复现场
				 ***"jmpq *0x00000000"		===>不显示字符串
				 );

	上面的代码主要是保存现场和恢复现场的代码多，所以看起来比较乱，为了程序的稳定性，还是需要这样做的，其实主要代码没有几行。

		
###so文件中，修改主程序代码，让原文件解密算法后，执行我们写的正则表达式代码：###
利用**mptect**,先把主程序要修改的代码段，修改为可写可执行：
	
	int mem_protect_open( char* start_addr , int len)
	{
	   unsigned int pagesize = 0;
	   pagesize=getpagesize();
	   char* ptr=(unsigned char *)((long)start_addr&(~(pagesize-1)));
	
	   return mprotect( ptr ,pagesize , PROT_READ|PROT_WRITE|PROT_EXEC);
	}


##编译so文件:##
	gcc -fPIC -shared -o myhook.so myhook.c -ldl -g
	加上-g，方便以后gdb调试

##LD_PRELOAD启动原程序并提前加载myhook.so文件:##
	LD_PRELOAD=./myhook.so ./原文件

##gdb中看so的注入情况:##
	
	用gdb调试程序：
	gdb attach pid
	
	(gdb) info shared
	From                To                  Syms Read   Shared Object Library
	0x00007f28329b4de0  0x00007f28329b57b8  Yes         ./myhook.so
	0x000000337700dba0  0x0000003377042d78  Yes (*)     /usr/lib64/libcurl.so.4
	0x0000003810002120  0x000000381000d3a8  Yes (*)     /lib64/libz.so.1
	0x000000380ec00de0  0x000000380ec01998  Yes (*)     /lib64/libdl.so.2
	0x000000380f802140  0x000000380f8054f8  Yes (*)     /lib64/librt.so.1
	0x000000380f405660  0x000000380f410eb8  Yes (*)     /lib64/libpthread.so.0
	0x0000003f77c563f0  0x0000003f77cc3376  Yes (*)     /usr/lib64/libstdc++.so.6
	0x000000380fc03e70  0x000000380fc43f48  Yes (*)     /lib64/libm.so.6
	0x0000003f77802910  0x0000003f77812f78  Yes (*)     /lib64/libgcc_s.so.1
	0x000000380f01ea20  0x000000380f13f76c  Yes (*)     /lib64/libc.so.6
	0x000000380e800b00  0x000000380e8198db  Yes (*)     /lib64/ld-linux-x86-64.so.2
	0x0000003811002f00  0x0000003811007418  Yes (*)     /lib64/libidn.so.11
	0x000000381280e750  0x000000381283b408  Yes (*)     /lib64/libldap-2.4.so.2
	0x000000381dc0ac30  0x000000381dc38728  Yes (*)     /lib64/libgssapi_krb5.so.2
	0x000000381c41b430  0x000000381c494a78  Yes (*)     /lib64/libkrb5.so.3
	0x000000381c0043d0  0x000000381c01d5a8  Yes (*)     /lib64/libk5crypto.so.3
	0x000000381d000ee0  0x000000381d001db8  Yes (*)     /lib64/libplds4.so
	0x000000381d401410  0x000000381d402b48  Yes (*)     /lib64/libplc4.so
	0x000000381cc0d210  0x000000381cc2cdd8  Yes (*)     /lib64/libnspr4.so
	0x000000381b4046e0  0x000000381b414578  Yes (*)     /usr/lib64/libsasl2.so.2
	0x000000381bc02a40  0x000000381bc080c8  Yes (*)     /lib64/libkrb5support.so.0
	0x000000381b000bf0  0x000000381b0011d8  Yes (*)     /lib64/libkeyutils.so.1
	0x0000003376818200  0x00000033768538d8  Yes (*)     /usr/lib64/libssl.so.10
	0x0000003376469d80  0x000000337655ef98  Yes (*)     /usr/lib64/libcrypto.so.10
	0x0000003817400c00  0x00000038174059a8  Yes (*)     /lib64/libcrypt.so.1
	0x0000003810805850  0x0000003810815cc8  Yes (*)     /lib64/libselinux.so.1
	0x00000038170036c0  0x000000381704a868  Yes (*)     /lib64/libfreebl3.so
	0x00007f28316b61f0  0x00007f28316be648  Yes (*)     /lib64/libnss_files.so.2
	0x00007f28314af000  0x00007f28314b2328  Yes (*)     /lib64/libnss_dns.so.2

---
#调试：#
##在strcasecmp处调试:##

> 这个地方是系统内部，帮我们做的处理，我们无需关心，如果有兴趣的朋友可以看linux源码

##在patch后代码的地方调试:##

	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       mov     [rsp+338h+var_330], esi
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       mov     qword ptr [rsp+338h+var_338], rax ; int
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       mov     rsi, rbp        ; char *
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       call    decode_data ; 	 解密字符串
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                 	   jmp     cs:qword_4526BC   ==>调用myhook.so中的函数
	.text:XXXXXXXXXXXXXXXX 00 00 00 00 00 00                       qword_4526BC    dq 7F28329B5200h
	.text:XXXXXXXXXXXXXXXX 0F 84 44 02 00 00                       nop(6)

##测试效果：##

> 完全实现了需求，软件名字，我还是隐去了，大家都明白。。。。

---
#如何预防？#

1. 对mprotect进行anti，让mprotect失去作用。
	
		对代码段的属性进行检测，看有没有被修改为可写模式。
		通过hook mprtect的方式，静止对本程序进行使用mprtect。


2. 在加密/解密的代码段，进行保护，多次检查，防止被修改或注入。
	
		call前后的代码是不是被非法篡改。
		最好对加密解密后的字符串，进行一次或多次检测。
	

3. 调用系统函数的时候，自己指定路径去调用。

	> 可以效仿这段代码，最好能定义成一个宏，或者模板，方便调用

	    static void *handle = NULL;
	    static STRCASECMP old_strcasecmp = NULL;
	    if (!handle)
	    {
	        handle = dlopen ("libc.so.6",RTLD_LAZY);
	        old_strcasecmp = (STRCASECMP)dlsym (handle,"strcasecmp");
	    }



---
#结束#

2018/3/18 16:39:12 