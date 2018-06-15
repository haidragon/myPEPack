// mystub.cpp : 定义 DLL 应用程序的导出函数。
//
//CreateWindow         User32.dll
//GetModuleHandle      Kernel32.dll
//ShowWindow           User32.dll
//GetMessage           User32.dll
//RegisterClass        User32.dll
//DispatchMessage      User32.dll
//WindowProc    直接用
//PostQuitMessage      User32.dll
//DefWindowProc        User32.dll
//UpdateWindow         User32.dll
#include "stdafx.h"
#include "string"
#include "windows.h"
#include "direct.h"
#include "Shlobj.h"
#include "mystub.h"
#include "../aplib/aplib.h"
#pragma comment(lib, "..\\aplib\\aplib.lib")
//合并节
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
typedef int (WINAPI *LPMESSAGEBOX)(
	HWND, LPCTSTR,
	LPCTSTR, UINT
	); //MessageBoxW
typedef DWORD(WINAPI *LPGETPROCADDRESS)(
	HMODULE,
	LPCSTR
	);         // GetProcAddress
typedef HMODULE(WINAPI *LPLOADLIBRARYEX)(
	LPCTSTR, HANDLE, DWORD
	); // LoadLibaryEx
typedef HMODULE(WINAPI *GETModuleHandle)(
	_In_opt_ LPCTSTR lpModuleName
	);
typedef BOOL(WINAPI* SHOWWINDOW)(
	_In_ HWND hWnd,
	_In_ int  nCmdShow
	);
typedef BOOL(WINAPI* GteMessage)(
	_Out_    LPMSG lpMsg,
	_In_opt_ HWND  hWnd,
	_In_     UINT  wMsgFilterMin,
	_In_     UINT  wMsgFilterMax
	);
typedef LRESULT(WINAPI* DISpatchMessage)(
	_In_ const MSG *lpmsg
	);
typedef ATOM(WINAPI* REGisterClass)(
	_In_ const WNDCLASS *lpWndClass
	);
typedef HWND(WINAPI *CREateWindowEx)(
	_In_     DWORD     dwExStyle,
	_In_opt_ LPCTSTR   lpClassName,
	_In_opt_ LPCTSTR   lpWindowName,
	_In_     DWORD     dwStyle,
	_In_     int       x,
	_In_     int       y,
	_In_     int       nWidth,
	_In_     int       nHeight,
	_In_opt_ HWND      hWndParent,
	_In_opt_ HMENU     hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID    lpParam
	);
typedef VOID(WINAPI* POSTQuitMessage)(
	_In_ int nExitCode
	);
typedef LRESULT(WINAPI* DEFWindowProc)(
	_In_ HWND   hWnd,
	_In_ UINT   Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
	);
typedef BOOL(*UPDateWindow)(
	_In_ HWND hWnd
	);
typedef int (WINAPI* GETWindowText)(
	_In_  HWND   hWnd,
	_Out_ LPTSTR lpString,
	_In_  int    nMaxCount
	);
typedef int (WINAPI* GETWindowTextLength)(
	_In_ HWND hWnd
	);
typedef HWND(WINAPI* GETDlgItem)(
	_In_opt_ HWND hDlg,
	_In_     int  nIDDlgItem
	);
typedef BOOL(WINAPI* SETWindowText)(
	_In_     HWND    hWnd,
	_In_opt_ LPCTSTR lpString
	);
typedef BOOL(WINAPI* TRanslateMessage)(
	_In_ const MSG *lpMsg
	);
typedef LPVOID(WINAPI *MYVIRTUALALLOC)(
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD  flAllocationType,
	_In_     DWORD  flProtect
	);
typedef BOOL(WINAPI *MYVIRTUALFREE)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  dwFreeType
	);
typedef HMODULE(WINAPI *MYLOADLIBRARY)(
	_In_ LPCSTR lpLibFileName
	);
wchar_t g_wcbuf100[100] = { 0 };
wchar_t g_MIMA100[100] = L"haidragon";
wchar_t wStrtext[100] = L"请输入密码";
_declspec(thread) int g_num;
/////////////////////////////////////////////////////////////
//初始化
LPGETPROCADDRESS    g_funGetProcAddress			= nullptr;
LPLOADLIBRARYEX     g_funLoadLibraryEx		    = nullptr;
HMODULE             hModuleKernel32			    = nullptr;
HMODULE             hModuleUser32               = nullptr;
GETModuleHandle     g_funGetModuleHandle	    = nullptr;
LPMESSAGEBOX        g_funMessageBox			    = nullptr;
CREateWindowEx      g_funCreateWindowEx		    = nullptr;
POSTQuitMessage     g_funPostQuitMessage	    = nullptr;
DEFWindowProc       g_funDefWindowProc          = nullptr;
GteMessage          g_funGetMessage			    = nullptr;
REGisterClass       g_funRegisterClass		    = nullptr;
SHOWWINDOW          g_funShowWindow			    = nullptr;
UPDateWindow        g_funUpdateWindow		    = nullptr;
DISpatchMessage     g_funDispatchMessage        = nullptr;
GETWindowText       g_funGetWindowText          = nullptr;
GETWindowTextLength g_funGetWindowTextLength    = nullptr;
GETDlgItem          g_funGetDlgItem             = nullptr;
SETWindowText       g_funSetWindowText          = nullptr;
TRanslateMessage    g_funTranslateMessage       = nullptr;
MYVIRTUALALLOC      g_VirtualAlloc              = nullptr;
MYVIRTUALFREE       g_VirtualFree               = nullptr;
MYLOADLIBRARY    g_LoadLibraryA                 = nullptr;

DWORD g_dwImageBase;
DWORD g_oep;
void start();
PACKINFO g_PackInfo = { (DWORD)start };
//获取kernel32模块加载基址
DWORD GetKernel32Base()
{
	DWORD dwKernel32Addr = 0;
	__asm
	{
		push eax
		mov eax, dword ptr fs : [0x30] // eax = PEB的地址
		mov eax, [eax + 0x0C]          // eax = 指向PEB_LDR_DATA结构的指针
		mov eax, [eax + 0x1C]          // eax = 模块初始化链表的头指针InInitializationOrderModuleList
		mov eax, [eax]                 // eax = 列表中的第二个条目
		mov eax, [eax + 0x08]          // eax = 获取到的Kernel32.dll基址（Win7下获取的是KernelBase.dll的基址）
		mov dwKernel32Addr, eax
		pop eax
	}

	return dwKernel32Addr;
}

//获取GetProcAddress的基址
DWORD GetGPAFunAddr()
{
	DWORD dwAddrBase = GetKernel32Base();

	// 1. 获取DOS头、NT头
	PIMAGE_DOS_HEADER pDos_Header;
	PIMAGE_NT_HEADERS pNt_Header;
	pDos_Header = (PIMAGE_DOS_HEADER)dwAddrBase;
	pNt_Header = (PIMAGE_NT_HEADERS)(dwAddrBase + pDos_Header->e_lfanew);

	// 2. 获取导出表项
	PIMAGE_DATA_DIRECTORY   pDataDir;
	PIMAGE_EXPORT_DIRECTORY pExport;
	pDataDir = pNt_Header->OptionalHeader.DataDirectory;
	pDataDir = &pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT];
	pExport = (PIMAGE_EXPORT_DIRECTORY)(dwAddrBase + pDataDir->VirtualAddress);

	// 3、获取导出表的必要信息
	DWORD dwModOffset = pExport->Name;                                  // 模块的名称
	DWORD dwFunCount = pExport->NumberOfFunctions;                      // 导出函数的数量
	DWORD dwNameCount = pExport->NumberOfNames;                         // 导出名称的数量

	PDWORD pEAT = (PDWORD)(dwAddrBase + pExport->AddressOfFunctions);   // 获取地址表的RVA
	PDWORD pENT = (PDWORD)(dwAddrBase + pExport->AddressOfNames);       // 获取名称表的RVA
	PWORD pEIT = (PWORD)(dwAddrBase + pExport->AddressOfNameOrdinals);  //获取索引表的RVA
	// 4、获取GetProAddress函数的地址
	for (DWORD i = 0; i < dwFunCount; i++)
	{
		if (!pEAT[i])
		{
			continue;
		}

		// 4.1 获取序号
		DWORD dwID = pExport->Base + i;

		// 4.2 变量EIT 从中获取到 GetProcAddress的地址
		for (DWORD dwIdx = 0; dwIdx < dwNameCount; dwIdx++)
		{
			// 序号表中的元素的值 对应着函数地址表的位置
			if (pEIT[dwIdx] == i)
			{
				//根据序号获取到名称表中的名字
				DWORD dwNameOffset = pENT[dwIdx];
				char * pFunName = (char*)(dwAddrBase + dwNameOffset);

				//判断是否是GetProcAddress函数
				if (!strcmp(pFunName, "GetProcAddress"))
				{
					// 获取EAT的地址 并将GetProcAddress地址返回
					DWORD dwFunAddrOffset = pEAT[i];
					return dwAddrBase + dwFunAddrOffset;
				}
			}
		}
	}
	return -1;
}
//初始化API
bool InitializationAPI()
{
	g_num;//使用tls变量,产生tls节表
	//初始化
	g_funGetProcAddress              = (LPGETPROCADDRESS)   GetGPAFunAddr();
	g_funLoadLibraryEx				 = (LPLOADLIBRARYEX)    g_funGetProcAddress((HMODULE)GetKernel32Base(), "LoadLibraryExW");
	hModuleKernel32					 =                      g_funLoadLibraryEx(L"Kernel32.dll", NULL, NULL);
	hModuleUser32				     =                      g_funLoadLibraryEx(L"user32.dll", NULL, NULL);
	g_LoadLibraryA					 = (MYLOADLIBRARY)      g_funGetProcAddress(hModuleKernel32, "LoadLibraryA");
	g_funGetModuleHandle             = (GETModuleHandle)    g_funGetProcAddress(hModuleKernel32, "GetModuleHandleW");
	g_VirtualAlloc					 = (MYVIRTUALALLOC)     g_funGetProcAddress(hModuleKernel32, "VirtualAlloc");
	g_VirtualFree					 = (MYVIRTUALFREE)      g_funGetProcAddress(hModuleKernel32, "VirtualFree");
	g_funMessageBox					 = (LPMESSAGEBOX)       g_funGetProcAddress(hModuleUser32, "MessageBoxW");
	g_funCreateWindowEx				 = (CREateWindowEx)     g_funGetProcAddress(hModuleUser32, "CreateWindowExW");
	g_funPostQuitMessage			 = (POSTQuitMessage)    g_funGetProcAddress(hModuleUser32, "PostQuitMessage");
	g_funDefWindowProc				 = (DEFWindowProc)      g_funGetProcAddress(hModuleUser32, "DefWindowProcW");
	g_funGetMessage					 = (GteMessage)         g_funGetProcAddress(hModuleUser32, "GetMessageW");
	g_funRegisterClass				 = (REGisterClass)      g_funGetProcAddress(hModuleUser32, "RegisterClassW");
	g_funShowWindow					 = (SHOWWINDOW)         g_funGetProcAddress(hModuleUser32, "ShowWindow");
	g_funUpdateWindow				 = (UPDateWindow)       g_funGetProcAddress(hModuleUser32, "UpdateWindow");
	g_funDispatchMessage			 = (DISpatchMessage)    g_funGetProcAddress(hModuleUser32, "DispatchMessageW");
	g_funGetWindowText				 = (GETWindowText)      g_funGetProcAddress(hModuleUser32, "GetWindowTextW");
	g_funGetWindowTextLength         = (GETWindowTextLength)g_funGetProcAddress(hModuleUser32, "GetWindowTextLengthW");
	g_funGetDlgItem					 = (GETDlgItem)         g_funGetProcAddress(hModuleUser32, "GetDlgItem");
	g_funSetWindowText				 = (SETWindowText)      g_funGetProcAddress(hModuleUser32, "SetWindowTextW");
	g_funTranslateMessage			 = (TRanslateMessage)   g_funGetProcAddress(hModuleUser32, "TranslateMessage");

	g_dwImageBase					 = (DWORD)g_funGetModuleHandle(NULL);
	g_oep							 = g_PackInfo.TargetOepRva + g_dwImageBase;
}

void DealwithIAT()
{

	// 1.获取第一项iat项
	PIMAGE_IMPORT_DESCRIPTOR pImportTable =
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)g_PackInfo.ImportTableRva + g_dwImageBase);
	if (g_PackInfo.ImportTableRva) //如果没用导入表则跳过
	{
		HMODULE lib;
		IMAGE_THUNK_DATA *IAT, *INTable;
		IMAGE_IMPORT_BY_NAME *IatByName;

		while (pImportTable->Name)//(pImportTable->FirstThunk)
		{
			lib = g_LoadLibraryA((char *)(pImportTable->Name + (DWORD)g_dwImageBase));

			IAT = (IMAGE_THUNK_DATA *)(pImportTable->FirstThunk + (DWORD)g_dwImageBase);
			INTable = (IMAGE_THUNK_DATA *)((pImportTable->OriginalFirstThunk ? pImportTable->OriginalFirstThunk : pImportTable->FirstThunk) + (DWORD)g_dwImageBase);
			while (INTable->u1.AddressOfData)
			{
				if ((((DWORD)INTable->u1.Function) & 0x80000000) == 0)
				{
					IatByName = (IMAGE_IMPORT_BY_NAME *)((DWORD)INTable->u1.AddressOfData + (DWORD)g_dwImageBase);
					IAT->u1.Function = (DWORD)g_funGetProcAddress(lib, (char *)(IatByName->Name));
				}
				else
				{
					IAT->u1.Function = (DWORD)g_funGetProcAddress(lib, (LPCSTR)(INTable->u1.Ordinal & 0xFFFF));
				}
				INTable++;
				IAT++;
			}
			pImportTable++;
		}
	}
}
void FixReloc()
{

	//以下是重定位
	DWORD *tmp;
	if (g_PackInfo.RelocRva)  //如果没有重定位表表示不用重定位，跳过重定位代码
	{
		DWORD relocation = (DWORD)g_dwImageBase - g_PackInfo.ImageBase;
		IMAGE_BASE_RELOCATION  *relocationAddress = (IMAGE_BASE_RELOCATION*)(g_PackInfo.RelocRva + (DWORD)g_dwImageBase);

		while (relocationAddress->VirtualAddress != 0)
		{
			LPVOID rva = (LPVOID)((DWORD)g_dwImageBase + relocationAddress->VirtualAddress);
			DWORD BlockNum = (relocationAddress->SizeOfBlock - 8) / 2;
			if (BlockNum == 0) break;
			WORD *Offset = (WORD *)((DWORD)relocationAddress + 8);
			for (int i = 0; i < (int)BlockNum; i++)
			{
				if ((Offset[i] & 0xF000) != 0x3000) continue;
				tmp = (DWORD*)((Offset[i] & 0xFFF) + (DWORD)rva);
				*tmp = (*tmp) + relocation;
			}
			relocationAddress = (IMAGE_BASE_RELOCATION*)((DWORD)relocationAddress + relocationAddress->SizeOfBlock);
		}
	}
}

//解密
void Decode()
{

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_dwImageBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + g_dwImageBase);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	// 找到.text段,并解密
	while (TRUE)
	{
		if (!strcmp((char*)pSection->Name, ".text"))
		{
			PCHAR pStart = pSection->VirtualAddress + (PCHAR)g_dwImageBase;
			for (int i = 0; i < pSection->Misc.VirtualSize; i++)
			{
				pStart[i] ^= 0x20;
			}
			break;
		}
		pSection = pSection + 1;
	}
}
void Decompress()
{
	// 1.获取节区头首地址

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)g_dwImageBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + g_dwImageBase);
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);

	// 2.解压压缩区段
	PCHAR lpPacked = ((PCHAR)g_dwImageBase + g_PackInfo.packSectionRva);// 内存地址
	DWORD dwPackedSize = aPsafe_get_orig_size(lpPacked);// 获取解压后的大小
	PCHAR lpBuffer = (PCHAR)g_VirtualAlloc(NULL, dwPackedSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//申请内存
	aPsafe_depack(lpPacked, g_PackInfo.packSectionSize, lpBuffer, dwPackedSize);// 解压
	// 3.将各区段还原回去
	DWORD offset = 0;
	for (int i = 0; i < g_PackInfo.PackSectionNumber; i++)
	{
		// 区段的标号
		int index = g_PackInfo.PackInfomation[i][0];
		// 这个区段的SizeOfRawData
		int size = g_PackInfo.PackInfomation[i][1];
		int * pint = &size;
		PCHAR destionVA = (PCHAR)g_dwImageBase + pSecHeader[index].VirtualAddress;
		PCHAR srcVA = lpBuffer + offset;
		_asm {
			mov eax, eax
			mov eax, eax
			mov eax, eax
			mov eax, eax
			mov eax, eax
			mov eax, eax
		}
		//memcpy(destionVA, srcVA, size);
		_asm {
			mov esi, srcVA
			mov edi, destionVA
			mov ebx, pint
			mov ecx, [ebx]
			cld;地址增量传送
			rep movsb;rep执行一次串指令后ecx减一
		}
		offset += size;
	}
	g_VirtualFree(lpBuffer, dwPackedSize, MEM_DECOMMIT);

}
void MachineCheck()
{}
void CallTls()
{
	IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)g_dwImageBase;
	IMAGE_NT_HEADERS* lpNtHeader = (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + g_dwImageBase);

	// 如果tls可用,调用tls
	if (g_PackInfo.bIsTlsUseful == TRUE)
	{
		// 将tls回调函数表指针设置回去
		PIMAGE_TLS_DIRECTORY pTlsDir =
			(PIMAGE_TLS_DIRECTORY)(lpNtHeader->OptionalHeader.DataDirectory[9].VirtualAddress + g_dwImageBase);
		pTlsDir->AddressOfCallBacks = g_PackInfo.TlsCallbackFuncRva;

		PIMAGE_TLS_CALLBACK* lptlsFun =
			(PIMAGE_TLS_CALLBACK*)(g_PackInfo.TlsCallbackFuncRva - lpNtHeader->OptionalHeader.ImageBase + g_dwImageBase);
		while ((*lptlsFun) != NULL)
		{
			(*lptlsFun)((PVOID)g_dwImageBase, DLL_PROCESS_ATTACH, NULL);
			lptlsFun++;
		}
	}

}

void IATReloc()
{
	//读取IAT的dll , 获得dll加载基址; 读取IAT中的函数名 , 获得函数地址; 申请指定大小的空间

	// 1.获取第一项iat项
	PIMAGE_IMPORT_DESCRIPTOR pImportTable =
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)g_PackInfo.ImportTableRva + g_dwImageBase);
	if (g_PackInfo.ImportTableRva) //如果没用导入表则跳过
	{
		HMODULE lib;
		IMAGE_THUNK_DATA *IAT, *INTable;
		IMAGE_IMPORT_BY_NAME *IatByName;

		while (pImportTable->Name)//(pImportTable->FirstThunk)
		{
			lib = g_LoadLibraryA((char *)(pImportTable->Name + (DWORD)g_dwImageBase));

			IAT = (IMAGE_THUNK_DATA *)(pImportTable->FirstThunk + (DWORD)g_dwImageBase);
			INTable = (IMAGE_THUNK_DATA *)((pImportTable->OriginalFirstThunk ? pImportTable->OriginalFirstThunk : pImportTable->FirstThunk) + (DWORD)g_dwImageBase);
			while (INTable->u1.AddressOfData)
			{
				DWORD dwAddress;
				if ((((DWORD)INTable->u1.Function) & 0x80000000) == 0)
				{
					IatByName = (IMAGE_IMPORT_BY_NAME *)((DWORD)INTable->u1.AddressOfData + (DWORD)g_dwImageBase);
					dwAddress = (DWORD)g_funGetProcAddress(lib, (char *)(IatByName->Name));
				}
				else
				{
					dwAddress = (DWORD)g_funGetProcAddress(lib, (LPCSTR)(INTable->u1.Ordinal & 0xFFFF));
				}
				char *dllName = (char *)(pImportTable->Name + (DWORD)g_dwImageBase);

				// 只重定向这几个dll,如果所有的都重定向会出错
				if ((!strcmp(dllName, "kernel32.dll"))
					|| (!strcmp(dllName, "user32.dll"))
					|| (!strcmp(dllName, "advapi32.dll"))
					|| (!strcmp(dllName, "gdi32.dll")))
				{
					// 申请虚拟内存
					PCHAR virBuf = (PCHAR)g_VirtualAlloc(NULL, 7, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

					// 赋值机器码     
					// mov ebx,address ;jmp address   0xbb 00 00 00 00 ff e3
					virBuf[0] = 0xBB;
					*(DWORD*)(virBuf + 1) = dwAddress;
					virBuf[5] = 0xFF;
					virBuf[6] = 0xE3;

					// 将iat表填充为这个
					IAT->u1.Function = (DWORD)virBuf;
				}
				else
				{
					IAT->u1.Function = dwAddress;
				}



				INTable++;
				IAT++;
			}
			pImportTable++;
		}
	}
}
void _stdcall FusedFunc(DWORD funcAddress)
{
	_asm
	{
		jmp label1
		label2 :
		_emit 0xeb; //跳到下面的call
		_emit 0x04;
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB];
		 //执行EB 02  也就是跳到下一句
		 //call Init;// 获取一些基本函数的地址
		 // call下一条,用于获得eip
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		//-------跳到下面的call
		_emit 0xEB;
		_emit 0x0E;

		//-------花
		PUSH 0x0;
		PUSH 0x0;
		MOV EAX, DWORD PTR FS : [0];
		PUSH EAX;
		//-------花


		// fused:
		//作用push下一条语句的地址
		//pop eax;
		//add eax, 0x1b;
		/*push eax;*/
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];

		push funcAddress; //这里如果是参数传入的需要注意上面的add eax,??的??
		retn;

		jmp label3

			// 花
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		// 花
	label1:
		jmp label2
			label3 :
	}
}
// 壳程序
int g_num11 = 10;
void AntidumpFunc1() {}
void AllFunc()
{
	// 递归执行10次后执行壳程序
	if (!g_num11)
	{
		_asm
		{
			nop
			mov   ebp, esp
			push - 1
			push   0
			push   0
			mov   eax, fs:[0]
			push   eax
			mov   fs : [0], esp
			sub   esp, 0x68
			push   ebx
			push   esi
			push   edi
			pop   eax
			pop   eax
			pop   eax
			add   esp, 0x68
			pop   eax
			mov   fs : [0], eax
			pop   eax

			sub g_num11, 1

			pop   eax
			pop   eax
			pop   eax
			mov   ebp, eax

			push AllFunc
			call FusedFunc
		}
	}


	g_PackInfo.bIsDynamicEncryption;//动态加密
	g_PackInfo.bIsVerificationProtection;// 校验
	g_PackInfo.bIsAntiDebugging;// 反调试
	;
	g_PackInfo.bIsAntiDump;// 反dump

						   // 初始化

						   // 反dump1
	AntidumpFunc1();

	//FusedFunc((DWORD)Init);
	// 机器检查
	if (g_PackInfo.bIsRegisteredProtection)
	{
		FusedFunc((DWORD)MachineCheck);
	}
	// 解压缩
	if (g_PackInfo.bIsCompression)
	{
		FusedFunc((DWORD)Decompress);
	}
	// 代码段加密
	if (g_PackInfo.bIsNormalEncryption)
	{
		FusedFunc((DWORD)Decode);
	}
	// 修复重定位
	FusedFunc((DWORD)FixReloc);
	// 是否IAT重定向
	if (g_PackInfo.bIsApiRedirect)
	{
		FusedFunc((DWORD)IATReloc);
	}
	else
	{
		FusedFunc((DWORD)DealwithIAT);// 如果不,就普通修复IAT
	}
	// 处理tls
	FusedFunc((DWORD)CallTls);


}

//判断密码
int decide() {
	int a = 0;
	//wchar_t g_MIMA100[100] = L"haidragon"; // h68 a61 i69 d64   72	r  a61   67	g   6F	o   6E	n
	//wchar_t wStrtext[100] = L"请输入密码";*/
	__asm
	{
			push eax
			push ebx
			push ecx
			push edi
			push esi
		////////////////////////////////////////////////////////////
		mov ecx, 18
		mov edi, offset g_MIMA100;//正解密码
		mov esi, offset g_wcbuf100
			repz cmpsb
			je  T
			jmp F
			T :
		mov a, 1
			F :
			////////////////////////////////////////////////////////////
			pop esi
			pop edi
			pop ecx
			pop ebx
			pop eax
	}
	return a;
}



LRESULT CALLBACK WindowProc(
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
) {


	switch (uMsg)
	{
	case WM_CREATE: {
		wchar_t wStr[20] = L"窗口回调函数触发";
		wchar_t wStr2[20] = L"haha";
		g_funMessageBox(NULL, wStr, wStr2, NULL);
		/////////////////////////////////////////////////////////////////////////////////////
		DWORD dwStyle = ES_LEFT | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE;
		DWORD dwExStyle = WS_EX_CLIENTEDGE | WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR;
		HWND hWnd = g_funCreateWindowEx(
			dwExStyle, //dwExStyle 扩展样式
			L"Edit", //lpClassName 窗口类名
			wStrtext, //lpWindowName 窗口标题
			dwStyle, //dwStyle 窗口样式
			150, //x 左边位置
			100, //y 顶边位置
			200, //nWidth 宽度
			20, //nHeight 高度
			hwnd, //hWndParent 父窗口句柄
			(HMENU)0x1002, //ID
			g_funGetModuleHandle(0), //hInstance 应用程序句柄
			NULL //lpParam 附加参数
		);
		return 0;
		/////////////////////////////////////////////////////////////////////////////////
	}
	case WM_COMMAND: {
		WORD wId = LOWORD(wParam);
		WORD wCode = HIWORD(wParam);
		HANDLE hChild = (HANDLE)lParam;
		if (wId == 0x1001 && wCode == BN_CLICKED)
		{

			HWND hwndCombo = g_funGetDlgItem(hwnd, 0x1002);
			int cTxtLen = g_funGetWindowTextLength(hwndCombo);
			g_funGetWindowText(hwndCombo, g_wcbuf100, 100);

			wchar_t wStr[20] = L"按钮触发";
			wchar_t wStr2[20] = L"haha";
			g_funMessageBox(NULL, wStr, wStr2, NULL);
			wchar_t wStr3[20] = L"";
			if (decide() == 1) {
				//g_funPostQuitMessage(0);
				g_funShowWindow(hwnd, SW_HIDE);
				//运行壳代码
				FusedFunc((DWORD)AllFunc);
				//_asm jmp g_PackInfo.TargetOep;
				wchar_t wStr[20] = L"密码正确！！！";
				wchar_t wStr2[20] = L"haha";
				g_funMessageBox(NULL, wStr, wStr2, NULL);
				_asm jmp g_oep;
			}
			else {
				wchar_t wStr[20] = L"密码错误请重新输入！！！";
				wchar_t wStr2[20] = L"haha";
				g_funMessageBox(NULL, wStr, wStr2, NULL);
			}
			g_funSetWindowText(hwndCombo, wStr3);
			return 1;
		}
		break;
	}
	case WM_CLOSE:
	{
		g_funPostQuitMessage(0);
		//return 0;
		break;
	}

	}
	// 返回默认的窗口处理过程
	return g_funDefWindowProc(hwnd, uMsg, wParam, lParam);
}
void CtrateWin() {

	MSG msg = { 0 };
	wchar_t wStr[20] = L"allenboy";
	wchar_t wStr2[20] = L"haha";
	g_funMessageBox(NULL, wStr, wStr2, NULL);
	// 先注册窗口类
	WNDCLASS wcs = {};
	wcs.lpszClassName = L"dragon";
	wcs.lpfnWndProc = WindowProc;
	wcs.hbrBackground = (HBRUSH)(COLOR_CAPTIONTEXT + 1);
	/////////////////////////////////////////////////////////////////////////////////////////
	//RegisterClass
	//RegisterClass(&wcs);
	g_funRegisterClass(&wcs);
	//#define CreateWindowW(lpClassName, lpWindowName, dwStyle, x, y,\
		//nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam)
//注册窗口
//CreateWindowEx

//窗口类名一定要与上面的一致
	HWND hWnd = g_funCreateWindowEx(0L, L"dragon", L"haidragon", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
		500, 200, 500, 500,
		NULL, NULL, NULL, NULL);
	// 三种风格  WS_OVERLAPPEDWINDOW  WS_POPUPWINDOW  WS_CHILDWINDOW

	g_funCreateWindowEx(0L, L"BUTTON", L"ok", WS_CHILD | WS_VISIBLE,
		200, 150,// 在父窗口的客户区的位置，
		100, 50,// 宽 高
		hWnd,// 父窗口
		(HMENU)0x1001,// 如果是顶层窗口 就是菜单句柄 子窗口就是本身的ID
					  //GetModuleHandle
		g_funGetModuleHandle(0), NULL);

	//ShowWindow(hWnd, SW_SHOW);
	g_funShowWindow(hWnd, SW_SHOW);
	g_funUpdateWindow(hWnd);
	/*while (GetMessage(&msg, 0, 0, 0))
	{
	DispatchMessage(&msg);
	}*/
	while (g_funGetMessage(&msg, 0, 0, 0))
	{

		//DispatchMessage(&msg);
		g_funTranslateMessage(&msg);
		g_funDispatchMessage(&msg);
	}
}


//导出的start()函数 用于复制到增加的节
_declspec(naked) void start()
{
	// 花指令
	_asm
	{
		PUSH - 1
		PUSH 0
		PUSH 0
		MOV EAX, DWORD PTR FS : [0]
		PUSH EAX
		MOV DWORD PTR FS : [0], ESP
		SUB ESP, 0x68
		PUSH EBX
		PUSH ESI
		PUSH EDI
		POP EAX
		POP EAX
		POP EAX
		ADD ESP, 0x68
		POP EAX
		MOV DWORD PTR FS : [0], EAX
		POP EAX
		POP EAX
		POP EAX
		POP EAX
		MOV EBP, EAX
	}
	InitializationAPI();
	CtrateWin();
	/*Decode();
	_asm jmp g_PackInfo.TargetOep;*/
}
