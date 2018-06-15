#pragma once
typedef struct _PACKINFO
{
	DWORD StartAddress;	//它存储起始函数地址
	DWORD TlsIndex;		// tls序号
	DWORD TlsCallbackFuncRva;// tls回调函数指针数组
	DWORD TargetOepRva;		//用来存储目标程序的OEP的
	DWORD ImageBase;
	DWORD ImportTableRva;		//iat的rva
	DWORD RelocRva;		//重定位表rva


	DWORD PackSectionNumber;// 压缩区段数量
	DWORD packSectionRva; // 压缩区段的rva
	DWORD packSectionSize;//压缩区段的大小
	DWORD PackInfomation[50][2];// 压缩区段中每个区段的index和大小
	BOOL bIsTlsUseful;
	BOOL bIsCompression;
	BOOL bIsNormalEncryption;
	BOOL bIsRegisteredProtection;
	BOOL bIsDynamicEncryption;
	BOOL bIsVerificationProtection;
	BOOL bIsAntiDebugging;
	BOOL bIsApiRedirect;
	BOOL bIsAntiDump;
}PACKINFO, *PPACKINFO;

extern "C" _declspec(dllexport) PACKINFO g_PackInfo;
