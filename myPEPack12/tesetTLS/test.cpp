// TLStest.cpp : 定义控制台应用程序的入口点。
//
#include<iostream>
#include "windows.h"
__declspec (thread) int g_nNum = 0x11111111;
__declspec (thread) char g_szStr[] = "TLS g_nNum = 0x%p ...\r\n";
__declspec(thread) char g_tlsNum[10] = "haha";
void NTAPI t_TlsCallBack_A(PVOID DllHandle, DWORD Reason, PVOID Red)
{
	if (DLL_PROCESS_ATTACH == Reason)
	{
		MessageBoxA(0, g_tlsNum, 0, 0);
		printf("t_TlsCallBack_B -> ThreadDetach!\r\n");
	}
}
void NTAPI t_TlsCallBack_B(PVOID DllHandle, DWORD Reason, PVOID Red)
{
	if (DLL_THREAD_DETACH == Reason)	//如果线程退出则打印小心
	{
		MessageBoxA(0, g_tlsNum, 0, 0);
		printf("t_TlsCallBack_B -> ThreadDetach!\r\n");
	}
	return;
}
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback[] = {
	t_TlsCallBack_A,t_TlsCallBack_B,
	NULL
};
#pragma data_seg()

DWORD WINAPI MyThreadProc(
	_In_ LPVOID lpParameter
)
{
	MessageBoxA(0, g_tlsNum, 0, 0);
	printf("t_Thread -> first printf:");
	printf(g_szStr, g_nNum);
	g_nNum = 0x22222222;
	printf("t_Thread -> second printf:");
	printf(g_szStr, g_nNum);
	return 0;
	return 0;
}

int main()
{
	MessageBoxA(0, g_tlsNum, 0, 1);
	CreateThread(NULL, 0, MyThreadProc, NULL, 0, NULL);
	CreateThread(NULL, 0, MyThreadProc, NULL, 0, NULL);
	system("pause");
	return 0;
}

