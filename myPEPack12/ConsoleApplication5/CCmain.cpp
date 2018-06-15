// ConsoleApplication5.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include"PEpack.h"
#include "../mystub/mystub.h"
#include<iostream>
#include<string>
using namespace std;
#define PATH _T("E:\\allenboy.exe")
bool Pack(
	BOOL bIsCompression,
	BOOL bIsNormalEncryption,
	BOOL bIsRegisteredProtection,
	BOOL bIsDynamicEncryption,
	BOOL bIsVerificationProtection,
	BOOL bIsAntiDebugging,
	BOOL bIsApiRedirect,
	BOOL bIsAntiDump,
	PCHAR pPath)
{
	BOOL ret = FALSE;
	//1 把stub.dll载入到内存
	HMODULE hStub = LoadLibrary(_T("..//release//mystub.dll"));
	//3 在内存中找到和stub.dll通讯的 g_PackInfo
	PPACKINFO pPackInfo = (PPACKINFO)GetProcAddress(hStub, "g_PackInfo");
	PEpack obj;
	obj.ReadTargetFile(pPath, pPackInfo);

	// 获取tls信息
	BOOL bTlsUseful = obj.DealwithTLS(pPackInfo);


	// 对代码段进行加密
	if (bIsNormalEncryption)
	{
		obj.Encode();
	}

	// 对各区段进行压缩
	if (bIsCompression)
	{
		obj.CompressPE(pPackInfo);
	}



	//2 获取stub.dll的内存大小和节区头(也就是要拷贝的头部)
	PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)hStub;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + (PCHAR)hStub);
	DWORD dwImageSize = pNt->OptionalHeader.SizeOfImage;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);


	//4 找到了之后，设置好跳转的OEP
	pPackInfo->TargetOepRva = obj.GetOepRva();
	// 设置Iamgebase
	pPackInfo->ImageBase = obj.GetImageBase();
	// 设置好选项

	pPackInfo->bIsCompression = bIsCompression;                      //压缩
	pPackInfo->bIsNormalEncryption = bIsNormalEncryption;            //加密
	pPackInfo->bIsRegisteredProtection = bIsRegisteredProtection;    //注册保护
	pPackInfo->bIsDynamicEncryption = bIsDynamicEncryption;          //动态加解密
	pPackInfo->bIsVerificationProtection = bIsVerificationProtection;//校验合保护
	pPackInfo->bIsAntiDebugging = bIsAntiDebugging;                  //反调式
	pPackInfo->bIsApiRedirect = bIsApiRedirect;                      //api重定向
	pPackInfo->bIsAntiDump = bIsAntiDump;                            //反转dump
	// 设置好重定位表rva和导入表的rva
	pPackInfo->ImportTableRva = obj.GetImportTableRva();
	pPackInfo->RelocRva = obj.GetRelocRva();

	//5 获得Start函数的Rva
	DWORD dwStartRva = (DWORD)pPackInfo->StartAddress - (DWORD)hStub;
	// ---在修改完所有通讯结构体的内容之后再对dll进行内存拷贝---
	//6 由于直接在本进程中修改会影响进程,所以将dll拷贝一份到pStubBuf
	PCHAR pStubBuf = new CHAR[dwImageSize];
	memcpy_s(pStubBuf, dwImageSize, (PCHAR)hStub, dwImageSize);

	//7 修复dll文件重定位,这里第二个参数应该传入hStub,因为这是dll加载时重定位的依据
	obj.FixDllRloc(pStubBuf, (PCHAR)hStub);

	//8 把stub部分的代码段添加为目标程序的新区段

	DWORD NewSectionRva = obj.AddSection(
		".stub",
		pSection->VirtualAddress + pStubBuf,
		pSection->SizeOfRawData,
		pSection->Characteristics
	);
	obj.SetTls(NewSectionRva, (PCHAR)hStub, pPackInfo);

	//=================重定位相关====================
	// 可以选择去掉重定位
	//obj.CancleRandomBase();
	// 或者将stub的重定位区段粘到最后面,将重定位项指向之,但是这之前也必须FixDllRloc,使其适应新的PE文件
	obj.ChangeReloc(pStubBuf);

	//9 把目标程序的OEP设置为stub中的start函数

	DWORD dwChazhi = (dwStartRva - pSection->VirtualAddress);
	DWORD dwNewOep = (dwChazhi + NewSectionRva);
	obj.SetNewOep(dwNewOep);

	// 设置每个区段可写
	obj.SetMemWritable();
	// 对IAT进行加密
	obj.ChangeImportTable();

	FreeLibrary(hStub);
	//10 保存成文件
	string savePath = pPath;
	savePath = savePath + "_pack.exe";
	obj.SaveNewFile((char*)savePath.c_str());


	return ret;
}
int main()
{
	PEpack obj;
                    
	//BOOL bIsCompression,            //压缩
	//BOOL bIsNormalEncryption,       //加密  
	//BOOL bIsRegisteredProtection,  //注册保护
	//BOOL bIsDynamicEncryption,     //动态加解密
	//BOOL bIsVerificationProtection,//校验合保护
	//BOOL bIsAntiDebugging,  //反调式
	//BOOL bIsApiRedirect,//api重定向
	//BOOL bIsAntiDump,//反转dump
	Pack(1, 1, 1, 1, 1, 1, 1, 1,"E:\\allenboy.exe");
    return 0;
}

