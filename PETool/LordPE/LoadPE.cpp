///////////////////////////////////////////////////////////////////////
// 说明：                                                            //
// 这是一个简单的PE文件分析工具，没有什么技术含量，完全是照着结构体  //
// 对PE文件进行一些解析操作。而且解析的部分很少；数据目录表部分只解  //
// 析了导入表部分。                                                  //
///////////////////////////////////////////////////////////////////////
// 作者信息                                                          //
// 作者：代码疯子                                                    //
// 博客：http://www.programlife.net/                                 //
// 邮箱：stackexploit@gmail.com                                      //
///////////////////////////////////////////////////////////////////////
// 特别提醒：                                                        //
// 本软件是一个典型的半成品工具，本软件仅供学习交流之用，请不要在正式//
// 场合或者重要场合等使用本软件，否则由此造成的一切后果作者概不负责。//
///////////////////////////////////////////////////////////////////////
// 版权申明                                                          //
// 本软件版权归作者代码疯子所有，转载请保留本段文字！                //
///////////////////////////////////////////////////////////////////////
// 有些地方本应该是把编辑框设为只读的，被我搞成禁用了，懒得改了      //
///////////////////////////////////////////////////////////////////////
#include <windows.h>
#include <commctrl.h>
#include <Tlhelp32.h>
#include "resource.h"

#pragma comment(lib, "comctl32")

HWND			g_hWnd;
HINSTANCE		g_hInstance;
TCHAR			szSrcTitle[] = TEXT("PEViewer");
TCHAR			szDstTitle[MAX_PATH + 32] = TEXT("");
static TCHAR	szFileName[MAX_PATH];

//
DLGPROC			g_oldMailProc;
DLGPROC			g_oldBlogProc;
HWND			g_hMailWnd;
HWND			g_hBlogWnd;

DWORD			g_dwMask;		// 时间掩码
DWORD			g_dwImageBase;	// 镜像基址
HANDLE			g_hFile;		// 文件句柄

void UnImplementationTips()
{
	MessageBox(g_hWnd,
		TEXT("此功能还没有实现 (⊙o⊙)…"),
		TEXT("简单PE分析"),
		MB_OK);
}

BOOL GetPeFilePath(TCHAR szFileName[])
{
	OPENFILENAME ofn;
	TCHAR szFile[MAX_PATH];
	ZeroMemory(szFile, sizeof(szFile));
	ZeroMemory(&ofn, sizeof(ofn));

	ofn.lStructSize		= sizeof(ofn);
	ofn.lpstrFile		= szFile;
	ofn.nMaxFile		= sizeof(szFile);
	ofn.lpstrFilter		= TEXT("*.exe\0*.exe\0")
						  TEXT("*.dll\0*.dll\0")
						  TEXT("All Files\0*.*\0");
	ofn.nFilterIndex	= 1;
	ofn.Flags			= OFN_HIDEREADONLY | OFN_PATHMUSTEXIST
						  | OFN_FILEMUSTEXIST;
	ofn.hwndOwner		= g_hWnd;

	if (GetOpenFileName(&ofn))
	{
		lstrcpy(szFileName, szFile);
		return TRUE;
	}
	return FALSE;
}

void EmptyCtrlValues()
{
	DWORD dwCtrlIDStart	= 1001;
	DWORD dwCtrlIDEnd	= 1016;
	for (DWORD dwIndex = dwCtrlIDStart; dwIndex <= dwCtrlIDEnd; ++dwIndex)
	{
		SetDlgItemText(g_hWnd, dwIndex, TEXT(""));
	}
	SetWindowText(g_hWnd, szSrcTitle);
}

void SetCtrlStyles()
{
	DWORD dwCtrlIDStart	= 1001;
	DWORD dwCtrlIDEnd	= 1016;
	for (DWORD dwIndex = dwCtrlIDStart; dwIndex <= dwCtrlIDEnd; ++dwIndex)
	{
		DWORD dwStyles = GetWindowLong(
							GetDlgItem(g_hWnd, dwIndex),
							GWL_STYLE);
		dwStyles |= ES_RIGHT;
		SetWindowLong(
			GetDlgItem(g_hWnd, dwIndex),
			GWL_STYLE,
			dwStyles);
	}
	HICON hIcon = LoadIcon(g_hInstance, MAKEINTRESOURCE(IDI_MAIN));
	SendMessage(g_hWnd, WM_SETICON, WPARAM(ICON_BIG), (LPARAM)(hIcon));
}

void SetCtrlValues(HANDLE hFile)
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	IMAGE_FILE_HEADER fileHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;

	TCHAR szText[256] = TEXT("");
	TCHAR szFormat8[] = TEXT("%08X");
	TCHAR szFormat4[] = TEXT("%04X");
	DWORD dwOffset = 0, dwTemp;

	lstrcpy(szDstTitle, szSrcTitle);
	lstrcat(szDstTitle, TEXT(" - "));
	lstrcat(szDstTitle, szFileName);
	SetWindowText(g_hWnd, szDstTitle);

	ReadFile(hFile, &dosHeader, sizeof(dosHeader), &dwTemp, NULL);
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		MessageBox(g_hWnd, TEXT("该文件不是有效的PE文件！(找不到MZ)"),
			TEXT("提示信息"), MB_ICONWARNING);
		return ;
	}
	
	dwOffset = dosHeader.e_lfanew;
	SetFilePointer(hFile, dwOffset, 0, FILE_BEGIN);
	ReadFile(hFile, &ntHeader, sizeof(ntHeader), &dwTemp, NULL);

	fileHeader = ntHeader.FileHeader;
	optionalHeader = ntHeader.OptionalHeader;

	if (ntHeader.Signature != IMAGE_NT_SIGNATURE)
	{
		MessageBox(g_hWnd, TEXT("该文件不是有效的PE文件！(找不到PE)"),
			TEXT("提示信息"), MB_ICONWARNING);
		return ;
	}

	// 入口点RVA
	wsprintf(szText, szFormat8, optionalHeader.AddressOfEntryPoint);
	SetDlgItemText(g_hWnd, IDC_EDIT_ENTRYPOINT, szText);
	// 装载地址
	wsprintf(szText, szFormat8, optionalHeader.ImageBase);
	SetDlgItemText(g_hWnd, IDC_EDIT_IMAGEBASE, szText);
	g_dwImageBase = optionalHeader.ImageBase;
	// 镜像大小
	wsprintf(szText, szFormat8, optionalHeader.SizeOfImage);
	SetDlgItemText(g_hWnd, IDC_EDIT_IMAGESIZE, szText);
	// 代码基址
	wsprintf(szText, szFormat8, optionalHeader.BaseOfCode);
	SetDlgItemText(g_hWnd, IDC_EDIT_CODEBASE, szText);
	// 数据基址
	wsprintf(szText, szFormat8, optionalHeader.BaseOfData);
	SetDlgItemText(g_hWnd, IDC_EDIT_DATABASE, szText);
	// 块对齐
	wsprintf(szText, szFormat8, optionalHeader.SectionAlignment);
	SetDlgItemText(g_hWnd, IDC_EDIT_MEMORYALIGN, szText);
	// 文件对齐
	wsprintf(szText, szFormat8, optionalHeader.FileAlignment);
	SetDlgItemText(g_hWnd, IDC_EDIT_FILEALIGN, szText);
	// 标志字
	wsprintf(szText, szFormat4, optionalHeader.Magic);
	SetDlgItemText(g_hWnd, IDC_EDIT_MAGIC, szText);
	// 子系统
	wsprintf(szText, szFormat4, optionalHeader.Subsystem);
	SetDlgItemText(g_hWnd, IDC_EDIT_SUBSYSTEM, szText);
	// 区段数目
	wsprintf(szText, szFormat4, fileHeader.NumberOfSections);
	SetDlgItemText(g_hWnd, IDC_EDIT_SECTIONNUM, szText);
	// 时间日期标志
	// 保存全局信息
	g_dwMask = fileHeader.TimeDateStamp;
	wsprintf(szText, szFormat8, fileHeader.TimeDateStamp);
	SetDlgItemText(g_hWnd, IDC_EDIT_TIMEDATE, szText);
	// 首部大小
	wsprintf(szText, szFormat8, optionalHeader.SizeOfHeaders);
	SetDlgItemText(g_hWnd, IDC_EDIT_HEADERSIZE, szText);
	// 特征值
	wsprintf(szText, szFormat4, fileHeader.Characteristics);
	SetDlgItemText(g_hWnd, IDC_EDIT_CHARACTER, szText);
	// 校验和
	wsprintf(szText, szFormat8, optionalHeader.CheckSum);
	SetDlgItemText(g_hWnd, IDC_EDIT_CHECKSUM, szText);
	// 可选头大小
	wsprintf(szText, szFormat4, fileHeader.SizeOfOptionalHeader);
	SetDlgItemText(g_hWnd, IDC_EDIT_OPTIONALSIZE, szText);
	// RVA数及大小
	wsprintf(szText, szFormat8, optionalHeader.NumberOfRvaAndSizes);
	SetDlgItemText(g_hWnd, IDC_EDIT_RVASIZE, szText);
}

// 需要将空间的notify属性设置为TRUE
BOOL CALLBACK StaticProc(HWND hwndDlg, 
						   UINT uMsg, 
						   WPARAM wParam, 
						   LPARAM lParam
						   )
{
	static TCHAR szBuffer[256];
	static WORD	 wFlag = 0;
	switch (uMsg)
	{
	case WM_MOUSEMOVE:
		SetCursor(LoadCursor(NULL, IDC_HAND));
		return TRUE;

	case WM_LBUTTONDOWN:
		SetCursor(LoadCursor(NULL, IDC_HAND));
		return TRUE;

	case WM_LBUTTONUP:
		GetWindowText(hwndDlg, szBuffer, 
			sizeof(szBuffer)/sizeof(szBuffer[0]));
		ShellExecute(NULL, TEXT("open"),
			szBuffer,
			NULL, NULL,
			SW_SHOWNORMAL);
		return TRUE;

	default:
		SetCursor(LoadCursor(NULL, IDC_ARROW));
		if (hwndDlg == g_hMailWnd)
		{
			return g_oldMailProc(hwndDlg, uMsg, wParam, lParam);
		}
		else if (hwndDlg == g_hBlogWnd)
		{
			return g_oldBlogProc(hwndDlg, uMsg, wParam, lParam);
		}
		break;
	}
	return 0;
}

// 时间编码到具体日期转换过程
void MaskTimeConvert(SYSTEMTIME& stTime,
					 DWORD& dwMask,
					 BOOL Mask2Time = TRUE)
{
	// GMT时间1970年1月1号
	SYSTEMTIME sysTime1970;
	ZeroMemory(&sysTime1970, sizeof(SYSTEMTIME));
	sysTime1970.wYear		= 1970;
	sysTime1970.wMonth		= 1;
	sysTime1970.wDay		= 1;

	LARGE_INTEGER li;
	li.QuadPart = 0;
	// 默认为掩码到日期的转换
	if (Mask2Time)
	{
		// 转为文件时间(100纳秒为单位)
		FILETIME fTime1970;
		SystemTimeToFileTime(&sysTime1970, &fTime1970);
		// 将掩码转换为100纳秒的单位
		li.LowPart = dwMask;
		li.QuadPart *= 1000 * 1000 * 10;
		li.LowPart += fTime1970.dwLowDateTime;
		li.HighPart += fTime1970.dwHighDateTime;
		// 将掩码转到文件时间
		FILETIME fTime;
		fTime.dwLowDateTime = li.LowPart;
		fTime.dwHighDateTime = li.HighPart;
		// 将文件时间转换为GMT时间
		FileTimeToSystemTime(&fTime, &stTime);

		return ;
	}
	else//Time2Mask
	{
		// 转为文件时间(100纳秒为单位)
		FILETIME fTime1970;
		SystemTimeToFileTime(&sysTime1970, &fTime1970);
		// 将现有时间转换为文件时间
		FILETIME fTimeNow;
		SystemTimeToFileTime(&stTime, &fTimeNow);
		// 时间差值计算
		fTimeNow.dwLowDateTime -= fTime1970.dwLowDateTime;
		fTimeNow.dwHighDateTime -= fTime1970.dwHighDateTime;
		// 将文件时间转换为秒数
		li.LowPart = fTimeNow.dwLowDateTime;
		li.HighPart = fTimeNow.dwHighDateTime;
		li.QuadPart /= (1000 * 1000 * 10);
		///////////////////////////////////
		// 不知道为什么这里有一个秒钟的损失
		///////////////////////////////////
		li.QuadPart += 1;
		// 转为字符串
		dwMask = li.LowPart;

		return ;
	}
}

BOOL CALLBACK TimeDlgProc(HWND hwndDlg, 
						   UINT uMsg, 
						   WPARAM wParam, 
						   LPARAM lParam
						   )
{
	static HWND			hRadioWnd;
	static TCHAR		szTimeMask[16];
	static DWORD		dwMask;
	static SYSTEMTIME	stTime;
	static TCHAR		szBuffer[32];

	switch (uMsg)
	{
	case WM_INITDIALOG:
		// 单选按钮的选择
		CheckRadioButton(hwndDlg,
			IDC_RADIO_SETMASK,
			IDC_RADIO_SETTIME,
			IDC_RADIO_SETMASK);
		// 禁用控件
		SendMessage(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_TIME), EM_SETREADONLY, TRUE, 0);
		//EnableWindow(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_TIME), FALSE);
		EnableWindow(GetDlgItem(hwndDlg, IDC_DLGTIME_DATE), FALSE);
		// 启用控件
		EnableWindow(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_MASK), TRUE);
		EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPYANDCLOSE), TRUE);
		// 获取主对话框的时间信息
		GetWindowText(GetDlgItem(g_hWnd, IDC_EDIT_TIMEDATE),
			szTimeMask,
			sizeof(szTimeMask) / sizeof(szTimeMask[0]));
		// 将时间信息传递给本对话框的编辑框控件
		SetWindowText(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_MASK),
			szTimeMask);
		///////////////////////////////////////////////////////////
		// 设置正确时间选项
		dwMask = g_dwMask;
		MaskTimeConvert(stTime, dwMask, TRUE);
		// 更新时间
		ZeroMemory(szBuffer, sizeof(szBuffer));
		wsprintf(szBuffer, TEXT("%02d:%02d:%02d"),
			stTime.wHour, stTime.wMinute, stTime.wSecond);
		SetWindowText(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_TIME),
			szBuffer);
		// 更新日期
		ZeroMemory(szBuffer, sizeof(szBuffer));
		DateTime_SetSystemtime(
			GetDlgItem(hwndDlg, IDC_DLGTIME_DATE),
			GDT_VALID,
			&stTime);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_RADIO_SETMASK:
			// 单选按钮的选择
			CheckRadioButton(hwndDlg,
				IDC_RADIO_SETMASK,
				IDC_RADIO_SETTIME,
				IDC_RADIO_SETMASK);
			// 禁用控件
			EnableWindow(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_TIME), FALSE);
			EnableWindow(GetDlgItem(hwndDlg, IDC_DLGTIME_DATE), FALSE);
			// 启用控件
			EnableWindow(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_MASK), TRUE);
			EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPYANDCLOSE), TRUE);
			///////////////////////////////////////////////
			// 时间信息转换为编码
			// 获取日期信息
			DateTime_GetSystemtime(
				GetDlgItem(hwndDlg, IDC_DLGTIME_DATE),
				&stTime);
			// 获取时间信息
			GetDlgItemText(hwndDlg, IDC_EDIT_DLGTIME_TIME,
				szBuffer, sizeof(szBuffer)/sizeof(szBuffer[0]));
			if (szBuffer[0] >= '0' && szBuffer[0] <= '9')
			{
				stTime.wHour = (szBuffer[0] - '0') * 10 + (szBuffer[1] - '0');
				stTime.wMinute = (szBuffer[3] - '0') * 10 + (szBuffer[4] - '0');
				stTime.wSecond = (szBuffer[6] - '0') * 10 + (szBuffer[7] - '0');
				// 编码转换
				MaskTimeConvert(stTime, dwMask, FALSE);
				// 转为字符串
				ZeroMemory(szBuffer, sizeof(szBuffer));
				wsprintf(szBuffer, TEXT("%08X"), dwMask);
				// 判断是否变化
				TCHAR szBuffer2[32];
				GetDlgItemText(hwndDlg, IDC_EDIT_DLGTIME_MASK,
					szBuffer2, sizeof(szBuffer2)/sizeof(szBuffer2[0]));
				if (!lstrcmp(szBuffer, szBuffer2))
				{
					return TRUE;
				}
				// 更新编码
				SetDlgItemText(hwndDlg,
					IDC_EDIT_DLGTIME_MASK,
					szBuffer);
			}

			return TRUE;

		case IDC_RADIO_SETTIME:
			CheckRadioButton(hwndDlg,
				IDC_RADIO_SETMASK,
				IDC_RADIO_SETTIME,
				IDC_RADIO_SETTIME);
			// 启用控件
			EnableWindow(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_TIME), TRUE);
			EnableWindow(GetDlgItem(hwndDlg, IDC_DLGTIME_DATE), TRUE);
			// 禁用控件
			EnableWindow(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_MASK), FALSE);
			EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_COPYANDCLOSE), FALSE);
			///////////////////////////////////////////////////////////
			// 获取时间文本
			GetDlgItemText(hwndDlg, IDC_EDIT_DLGTIME_MASK,
				szBuffer, sizeof(szBuffer)/sizeof(szBuffer[0]));
			// 将文本转换为十六进制数据
			dwMask = 0;
			for (int i = 0; i < lstrlen(szBuffer); ++i)
			{
				dwMask *= 16;
				if (szBuffer[i] >= '0' && szBuffer[i] <= '9')
				{
					dwMask += szBuffer[i] - '0';
				}
				else if (szBuffer[i] >= 'A' && szBuffer[i] <= 'F')
				{
					dwMask += szBuffer[i] - 'A' + 10;
				}
				else
				{
					MessageBox(hwndDlg, TEXT("数据格式错误！"),
						TEXT("警告"),
						MB_ICONERROR);
					SetDlgItemText(hwndDlg, IDC_EDIT_DLGTIME_MASK,
						TEXT(""));
					return TRUE;
				}
			}
			// 保存更改
			g_dwMask = dwMask;
			// 设置正确时间选项
			MaskTimeConvert(stTime, dwMask, TRUE);
			// 更新时间
			ZeroMemory(szBuffer, sizeof(szBuffer));
			wsprintf(szBuffer, TEXT("%02d:%02d:%02d"),
				stTime.wHour, stTime.wMinute, stTime.wSecond);
			SetWindowText(GetDlgItem(hwndDlg, IDC_EDIT_DLGTIME_TIME),
				szBuffer);
			// 更新日期
			ZeroMemory(szBuffer, sizeof(szBuffer));
			DateTime_SetSystemtime(
				GetDlgItem(hwndDlg, IDC_DLGTIME_DATE),
				GDT_VALID,
				&stTime);
			return TRUE;

		case IDC_BTN_COPYANDCLOSE:
			// 复制到剪贴板
			if (OpenClipboard(hwndDlg) && EmptyClipboard())
			{
				//获取数据
				HGLOBAL hMem;
				hMem = GlobalAlloc(GMEM_MOVEABLE,
					(lstrlen(szTimeMask) + sizeof(szTimeMask[0])) * sizeof(szTimeMask[0]));
				PVOID pBuff = (PVOID)GlobalLock(hMem);
				memcpy(pBuff, szTimeMask, 
					(lstrlen(szTimeMask) + sizeof(szTimeMask[0])) * sizeof(szTimeMask[0]));
				GlobalUnlock(hMem);

				//设置数据到剪贴板
				SetClipboardData(CF_UNICODETEXT, hMem);

				//关闭剪贴板
				CloseClipboard();
			}
			// 关闭窗体
			SendMessage(hwndDlg, WM_CLOSE, 0, 0);
			return TRUE;

		default:
			return FALSE;
		}

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;

	default:
		break;
	}
	return FALSE;
}

// 相对虚拟地址转换为虚拟地址
void RvaToVa(DWORD& dwRva, DWORD& dwVa)
{
	dwVa = g_dwImageBase + dwRva;
}

// 虚拟地址转换为相对虚拟地址
void VaToRva(DWORD& dwVa, DWORD& dwRva)
{
	dwRva = dwVa - g_dwImageBase;
}

// 文件偏移到虚拟地址
void OffsetToVa(DWORD& dwOffset, DWORD& dwVa)
{
	IMAGE_SECTION_HEADER	sectionHeader;
	IMAGE_SECTION_HEADER	emptyHeader;
	IMAGE_DOS_HEADER		dosHeader;

	DWORD	dwLength, dwTmp;
	DWORD	dwIndex = 0;
	// 定位到文件开始处
	SetFilePointer(g_hFile, 0, 0, FILE_BEGIN);
	// 读取IMAGE_DOS_HEADER
	ReadFile(g_hFile, &dosHeader, 
		sizeof(IMAGE_DOS_HEADER),
		&dwTmp,
		NULL);
	dwLength = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);
	// 定位到文件节表开始处
	SetFilePointer(g_hFile, dwLength, 0, FILE_BEGIN);
	// 判断偏移是否在节表之前
	if (dwOffset < dwLength)
	{
		dwVa = dwOffset + g_dwImageBase;
		return ;
	}
	// 解析节表
	ZeroMemory(&emptyHeader, sizeof(IMAGE_SECTION_HEADER));
	while (1)
	{
		++dwIndex;
		ReadFile(g_hFile, &sectionHeader,
			sizeof(IMAGE_SECTION_HEADER),
			&dwTmp,
			NULL);
		// 第一个节区
		if (dwIndex == 1 && dwOffset < sectionHeader.PointerToRawData)
		{
			dwVa = dwOffset + g_dwImageBase;
			return ;
		}
		if (!memcmp(&emptyHeader, &sectionHeader, sizeof(IMAGE_SECTION_HEADER)))
		{
			// 查找失败
			dwVa = 0;
			//MessageBox(g_hWnd, TEXT("地址超出范围了:-)"), TEXT("提示信息"), MB_ICONERROR);
			return ;
		}
		dwTmp = sectionHeader.PointerToRawData;
		if (dwOffset >= dwTmp && 
			dwOffset < dwTmp + sectionHeader.SizeOfRawData)
		{
			// 计算虚拟地址(RVA-基址)
			dwVa = sectionHeader.VirtualAddress 
				+ g_dwImageBase
				+ dwOffset - dwTmp;
			return ;
		}
	}

	return ;
}

// 文件偏移到相对虚拟地址
void OffsetToRva(DWORD& dwOffset, DWORD& dwRva)
{
	DWORD dwVa = 0;
	OffsetToVa(dwOffset, dwVa);
	VaToRva(dwVa, dwRva);
}

// 虚拟地址到文件偏移
void VaToOffset(DWORD& dwVa, DWORD& dwOffset)
{
	IMAGE_SECTION_HEADER	sectionHeader;
	IMAGE_SECTION_HEADER	emptyHeader;
	IMAGE_DOS_HEADER		dosHeader;

	DWORD	dwLength, dwTmp;
	DWORD	dwIndex = 0;
	// 定位到文件开始处
	SetFilePointer(g_hFile, 0, 0, FILE_BEGIN);
	// 读取IMAGE_DOS_HEADER
	ReadFile(g_hFile, &dosHeader, 
		sizeof(IMAGE_DOS_HEADER),
		&dwTmp,
		NULL);
	dwLength = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);
	// 定位到文件节表开始处
	SetFilePointer(g_hFile, dwLength, 0, FILE_BEGIN);
	// 判断偏移是否在节表之前
	if (dwVa - g_dwImageBase < dwLength)
	{
		dwOffset = dwVa - g_dwImageBase;
		return ;
	}
	// 解析节表
	ZeroMemory(&emptyHeader, sizeof(IMAGE_SECTION_HEADER));
	while (1)
	{
		++dwIndex;
		ReadFile(g_hFile, &sectionHeader,
			sizeof(IMAGE_SECTION_HEADER),
			&dwTmp,
			NULL);
		if (dwIndex == 1)	// 第一个节区
		{
			if (dwVa - g_dwImageBase < sectionHeader.VirtualAddress)
			{
				// 不需要转换
				// 偏移地址即为RVA
				dwOffset = dwVa - g_dwImageBase;
				return ;
			}
		}
		if (!memcmp(&emptyHeader, &sectionHeader, sizeof(IMAGE_SECTION_HEADER)))
		{
			// 查找失败
			dwOffset = 0;
			//MessageBox(g_hWnd, TEXT("地址超出范围了:-)"), TEXT("提示信息"), MB_ICONERROR);
			return ;
		}
		// 起始VA
		DWORD dwStartVa	= sectionHeader.VirtualAddress + g_dwImageBase;
		// 结束VA
		DWORD dwEndVa	= dwStartVa + sectionHeader.SizeOfRawData;
		if (dwVa >= dwStartVa && dwVa < dwEndVa)
		{
			// 计算虚拟地址(RVA-基址)
			dwOffset = dwVa - g_dwImageBase		// RVA
				- sectionHeader.VirtualAddress	// 起始RVA
				+ sectionHeader.PointerToRawData;
			return ;
		}
	}

	return ;
}

// 文件偏移到相对虚拟地址
void RvaToOffset(DWORD& dwRva, DWORD& dwOffset)
{
	DWORD dwVa = 0;
	RvaToVa(dwRva, dwVa);
	VaToOffset(dwVa, dwOffset);
	
}

// 根据RVA获取区段信息
void GetSectionNameByRva(DWORD dwRva, TCHAR szBuffer[])
{
	// 读取节表信息相关变量
	IMAGE_SECTION_HEADER	sectionHeader;
	IMAGE_SECTION_HEADER	emptyHeader;
	IMAGE_DOS_HEADER		dosHeader;

	DWORD	dwLength, dwTmp;
	DWORD	dwIndex = 0;
	int		i;

	// 读取节表信息
	dwIndex = 0;
	// 定位到文件开始处
	SetFilePointer(g_hFile, 0, 0, FILE_BEGIN);
	// 读取IMAGE_DOS_HEADER
	ReadFile(g_hFile, &dosHeader, 
		sizeof(IMAGE_DOS_HEADER),
		&dwTmp,
		NULL);
	/////////////////////////////////////////////////////////////////////////////
	// 判断RVA的位置是否在IMAGE_DOS_HEADER
	/////////////////////////////////////////////////////////////////////////////
	if (dwRva >= 0 && dwRva < sizeof(dosHeader))
	{
		lstrcpy(szBuffer, TEXT("IMAGE_DOS_HEADER"));
		return ;
	}
	dwLength = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);
	if (dwRva < (DWORD)(dosHeader.e_lfanew))
	{
		lstrcpy(szBuffer, TEXT("Dos Stub"));
		return ;
	}
	if (dwRva < dwLength)
	{
		lstrcpy(szBuffer, TEXT("IMAGE_NT_HEADERS"));
		return ;
	}
	// 定位到文件节表开始处
	SetFilePointer(g_hFile, dwLength, 0, FILE_BEGIN);
	// 解析节表
	ZeroMemory(&emptyHeader, sizeof(IMAGE_SECTION_HEADER));
	while (1)
	{
		ReadFile(g_hFile, &sectionHeader,
			sizeof(IMAGE_SECTION_HEADER),
			&dwTmp,
			NULL);
		if (!memcmp(&emptyHeader, &sectionHeader, sizeof(IMAGE_SECTION_HEADER)))
		{
			// 查找结束
			break;
		}
		/////////////////////////////////////////////////////////////////////////
		// 获取节名
		/////////////////////////////////////////////////////////////////////////
		ZeroMemory(szBuffer, sizeof(szBuffer));
		for (i = 0; i < IMAGE_SIZEOF_SHORT_NAME; ++i)
		{
			if (sectionHeader.Name[i] == '\0')
				break;
			szBuffer[i] = sectionHeader.Name[i];
		}
		szBuffer[i] = '\0';
		/////////////////////////////////////////////////////////////////////////
		// 判断地址范围
		/////////////////////////////////////////////////////////////////////////
		if (dwRva >= sectionHeader.VirtualAddress &&
			dwRva < sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize)
		{
			return ;
		}
	}
	lstrcpy(szBuffer, TEXT("无法定位地址"));
	return ;
}

BOOL CALLBACK AddressDlgProc(HWND hwndDlg, 
						   UINT uMsg, 
						   WPARAM wParam, 
						   LPARAM lParam
						   )
{
	DWORD	dwRva;		// 相对虚拟地址
	DWORD	dwVa;		// 虚拟地址
	DWORD	dwOffset;	// RAW偏移
	DWORD	dwTmp;		// 临时变量
	TCHAR	szBuffer[32];

	switch (uMsg)
	{
	case WM_INITDIALOG:
		// 单选按钮的选择
		CheckRadioButton(hwndDlg,
			IDC_RADIO_VA,
			IDC_RADIO_OFFSET,
			IDC_RADIO_RVA);
		// 禁用一些控件
		EnableWindow(
			GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_OFFSET),
			FALSE);
		EnableWindow(
			GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_VA),
			FALSE);
		EnableWindow(
			GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_RVA),
			TRUE);
		// 禁用区段文本框
		EnableWindow(
			GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_SECTION),
			FALSE);

		return TRUE;

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BTN_RVADLG_CLOSE:
			SendMessage(hwndDlg, WM_CLOSE, 0, 0);
			return TRUE;

		case IDC_RADIO_RVA:
			// 禁用一些控件
			EnableWindow(
				GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_OFFSET),
				FALSE);
			EnableWindow(
				GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_VA),
				FALSE);
			EnableWindow(
				GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_RVA),
				TRUE);
			return TRUE;

		case IDC_RADIO_VA:
			// 禁用一些控件
			EnableWindow(
				GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_OFFSET),
				FALSE);
			EnableWindow(
				GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_VA),
				TRUE);
			EnableWindow(
				GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_RVA),
				FALSE);

			return TRUE;

		case IDC_RADIO_OFFSET:
			// 禁用一些控件
			EnableWindow(
				GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_OFFSET),// 1035
				TRUE);
			EnableWindow(
				GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_VA),	// 1033
				FALSE);
			EnableWindow(
				GetDlgItem(hwndDlg, IDC_EDIT_RVADLG_RVA),	// 1034
				FALSE);
			return TRUE;

		case IDC_BTN_RVADLG_TRANS:
			if (g_hFile == NULL)
			{
				return TRUE;
			}
			for (int i = IDC_EDIT_RVADLG_VA; i <= IDC_EDIT_RVADLG_OFFSET; ++i)
			{
				// 判断是哪个单选按钮被选中了
				if (IsWindowEnabled(GetDlgItem(hwndDlg, i)))
				{
					// 清零操作
					ZeroMemory(szBuffer, sizeof(szBuffer));
					dwTmp = 0;
					// 提取数据
					GetDlgItemText(hwndDlg, i, szBuffer, sizeof(szBuffer)/sizeof(szBuffer[0]));
					// 转换操作
					for (int j = 0; j < lstrlen(szBuffer); ++j)
					{
						dwTmp *= 16;
						if (szBuffer[j] >= '0' && szBuffer[j] <= '9')
						{
							dwTmp += szBuffer[j] - '0';
						}
						else if (szBuffer[j] >= 'A' && szBuffer[j] <= 'F')
						{
							dwTmp += szBuffer[j] - 'A' + 10;
						}
					}
					// 地址转换计算
					if (i == IDC_EDIT_RVADLG_RVA)
					{
						dwRva = dwTmp;
						RvaToVa(dwRva, dwVa);
						RvaToOffset(dwRva, dwOffset);
					}
					else if (i == IDC_EDIT_RVADLG_VA)
					{
						dwVa = dwTmp;
						VaToRva(dwVa, dwRva);
						VaToOffset(dwVa, dwOffset);
					}
					else if (i == IDC_EDIT_RVADLG_OFFSET)
					{
						dwOffset = dwTmp;
						OffsetToRva(dwOffset, dwRva);
						OffsetToVa(dwOffset, dwVa);
					}
					// 更新数据
					ZeroMemory(szBuffer, sizeof(szBuffer));
					wsprintf(szBuffer, TEXT("%08X"), dwVa);
					SetDlgItemText(hwndDlg,
						IDC_EDIT_RVADLG_VA,
						szBuffer);
					wsprintf(szBuffer, TEXT("%08X"), dwRva);
					SetDlgItemText(hwndDlg,
						IDC_EDIT_RVADLG_RVA,
						szBuffer);
					wsprintf(szBuffer, TEXT("%08X"), dwOffset);
					SetDlgItemText(hwndDlg,
						IDC_EDIT_RVADLG_OFFSET,
						szBuffer);
					// 计算区段信息
					GetSectionNameByRva(dwRva, szBuffer);
					SetDlgItemText(hwndDlg, IDC_EDIT_RVADLG_SECTION, szBuffer);
					break;
				}
			}

		default:
			break;

		}

	default:
		break;
	}
	return FALSE;
}

BOOL CALLBACK AboutDlgProc(HWND hwndDlg, 
						 UINT uMsg, 
						 WPARAM wParam, 
						 LPARAM lParam
						 )
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		g_hMailWnd = GetDlgItem(hwndDlg, IDC_STATIC_MAIL);
		g_hBlogWnd = GetDlgItem(hwndDlg, IDC_STATIC_BLOG);

		g_oldBlogProc = (DLGPROC)SetWindowLong(g_hBlogWnd,
							GWL_WNDPROC,
							(LONG)StaticProc);
		g_oldMailProc = (DLGPROC)SetWindowLong(g_hMailWnd,
							GWL_WNDPROC,
							(LONG)StaticProc);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;

	default:
		break;
	}
	return FALSE;
}

BOOL CALLBACK SectionDlgProc(HWND hwndDlg, 
						   UINT uMsg, 
						   WPARAM wParam, 
						   LPARAM lParam
						   )
{
	static HWND	hListWnd;
	LV_COLUMN	lvc;
	LVITEM		lvi;
	DWORD		i;
	TCHAR		szText[256];
	TCHAR		lpColNames[6][32]	= {	TEXT("名称"), TEXT("VOffset"), TEXT("VSize"), 
										TEXT("ROffset"), TEXT("RSize"), TEXT("标志")};
	DWORD		dwColWidths[]	= {75, 75, 75, 75, 75, 75};

	// 读取节表信息相关变量
	IMAGE_SECTION_HEADER	sectionHeader;
	IMAGE_SECTION_HEADER	emptyHeader;
	IMAGE_DOS_HEADER		dosHeader;

	DWORD	dwLength, dwTmp;
	DWORD	dwIndex = 0;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		hListWnd = GetDlgItem(hwndDlg, IDC_LIST_SECTION);
		// 设置列表视图风格		
		// 行选中 + 网格
		ListView_SetExtendedListViewStyle(hListWnd, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvc.pszText = szText;
		lvc.iImage = 1;
		lvc.fmt = LVCFMT_LEFT;

		// 插入表头部分
		for (i = 0; i < 6; ++i)
		{
			lvc.pszText		= lpColNames[i];
			lvc.cx			= dwColWidths[i];
			lvc.iSubItem	= i;
			if (ListView_InsertColumn(hListWnd, i, &lvc) == -1)
			{
				return 0;
			}
		}

		if (g_hFile == NULL)
		{
			return TRUE;
		}
		
		// 读取节表信息
		dwIndex = 0;
		// 定位到文件开始处
		SetFilePointer(g_hFile, 0, 0, FILE_BEGIN);
		// 读取IMAGE_DOS_HEADER
		ReadFile(g_hFile, &dosHeader, 
			sizeof(IMAGE_DOS_HEADER),
			&dwTmp,
			NULL);
		dwLength = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);
		// 定位到文件节表开始处
		SetFilePointer(g_hFile, dwLength, 0, FILE_BEGIN);
		// 解析节表
		ZeroMemory(&emptyHeader, sizeof(IMAGE_SECTION_HEADER));
		while (1)
		{
			ReadFile(g_hFile, &sectionHeader,
				sizeof(IMAGE_SECTION_HEADER),
				&dwTmp,
				NULL);
			if (!memcmp(&emptyHeader, &sectionHeader, sizeof(IMAGE_SECTION_HEADER)))
			{
				// 查找结束
				break;
			}
			/////////////////////////////////////////////////////////////////////////
			// 插入数据
			/////////////////////////////////////////////////////////////////////////
			ZeroMemory(&lvi,sizeof(lvi));
			lvi.mask		= LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
			lvi.state		= 0;
			lvi.stateMask	= 0;
			lvi.iItem		= dwIndex;
			lvi.iImage		= 0;
			lvi.iSubItem	= 0;
			/////////////////////////////////////////////////////////////////////////
			// 获取节名
			/////////////////////////////////////////////////////////////////////////
			ZeroMemory(szText, sizeof(szText));
			for (i = 0; i < IMAGE_SIZEOF_SHORT_NAME; ++i)
			{
				if (sectionHeader.Name[i] == '\0')
					break;
				szText[i] = sectionHeader.Name[i];
			}
			// 插入数据
			lvi.pszText		= szText;
			lvi.cchTextMax	= lstrlen(lvi.pszText) + 1;
			ListView_InsertItem(hListWnd, &lvi);
			/////////////////////////////////////////////////////////////////////////
			// 获取RVA
			/////////////////////////////////////////////////////////////////////////
			TCHAR szRva[32], szFormat[32] = TEXT("%08X");
			wsprintf(szRva, szFormat, sectionHeader.VirtualAddress);
			ListView_SetItemText(hListWnd, dwIndex, 1, szRva);
			/////////////////////////////////////////////////////////////////////////
			// 获取虚拟地址大小
			/////////////////////////////////////////////////////////////////////////
			TCHAR szRvaSize[32];
			wsprintf(szRvaSize, szFormat, sectionHeader.Misc.VirtualSize);
			ListView_SetItemText(hListWnd, dwIndex, 2, szRvaSize);
			/////////////////////////////////////////////////////////////////////////
			// 获取物理偏移地址
			/////////////////////////////////////////////////////////////////////////
			TCHAR szOffset[32];
			wsprintf(szOffset, szFormat, sectionHeader.PointerToRawData);
			ListView_SetItemText(hListWnd, dwIndex, 3, szOffset);
			/////////////////////////////////////////////////////////////////////////
			// 获取物理地址大小
			/////////////////////////////////////////////////////////////////////////
			TCHAR szRawSize[32];
			wsprintf(szRawSize, szFormat, sectionHeader.SizeOfRawData);
			ListView_SetItemText(hListWnd, dwIndex, 4, szRawSize);
			/////////////////////////////////////////////////////////////////////////
			// 获取物理地址大小
			/////////////////////////////////////////////////////////////////////////
			TCHAR szFlag[32];
			wsprintf(szFlag, szFormat, sectionHeader.Characteristics);
			ListView_SetItemText(hListWnd, dwIndex, 5, szFlag);

			++dwIndex;
		}
		return TRUE;

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;

	default:
		break;
	}
	return FALSE;
}

/////////////////////////////////////////////////////////////////////
// 解析IMAGE_IMPORT_DESCRIPTOR
/////////////////////////////////////////////////////////////////////
void ParseIID(HWND& hListDll)
{
	if (g_hFile == NULL)
	{
		return ;
	}

	LVITEM			lvi;
	DWORD			i;
	TCHAR			szText[256];
	char			szBuffer[4];
	TCHAR			szFormat[] = TEXT("%08X");

	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_NT_HEADERS		ntHeader;
	IMAGE_DATA_DIRECTORY	dataDir;
	IMAGE_DATA_DIRECTORY	emptyDir;
	IMAGE_IMPORT_DESCRIPTOR	iid;
	IMAGE_IMPORT_DESCRIPTOR	emptyIid;

	DWORD			dwTmp;
	DWORD			dwStartRva;
	DWORD			dwOffset;
	DWORD			dwIndex;
	// 临时变量
	DWORD			dwTmpRva;
	DWORD			dwTmpOffset;
	
	// 设置文件偏移
	SetFilePointer(g_hFile, 0, 0, FILE_BEGIN);
	// 读取IMAGE_DOS_HEADER
	ReadFile(g_hFile, &dosHeader, sizeof(dosHeader),
		&dwTmp, NULL);
	// 设置文件偏移
	SetFilePointer(g_hFile, dosHeader.e_lfanew, 0, FILE_BEGIN);
	// 读取IMAGE_NT_HEADERS
	ReadFile(g_hFile, &ntHeader, sizeof(ntHeader), &dwTmp, NULL);
	// 数据目录表
	dataDir = ntHeader.OptionalHeader.DataDirectory[1];
	ZeroMemory(&emptyDir, sizeof(emptyDir));
	// 如果输出表为空
	if (!memcmp(&dataDir, &emptyDir, sizeof(dataDir)))
	{
		return ;
	}
	// 获取输入表RVA
	dwStartRva = dataDir.VirtualAddress;
	// 将RVA转化为偏移地址
	RvaToOffset(dwStartRva, dwOffset);
	// 设置文件偏移
	SetFilePointer(g_hFile, dwOffset, 0, FILE_BEGIN);

	// 开始读取IID
	ZeroMemory(&emptyIid, sizeof(emptyIid));
	dwIndex = 0;
	while (1)
	{
		ReadFile(g_hFile,
			&iid,
			sizeof(iid),
			&dwTmp,
			NULL);
		if (!memcmp(&iid, &emptyIid, sizeof(iid)))
		{
			return ;
		}
		/////////////////////////////////////////////////////////////////////////
		// 插入数据
		/////////////////////////////////////////////////////////////////////////
		// DllName	OriginalFirstThunk	TimeDateStamp	ForwarderChain	Name	FirstThunk
		ZeroMemory(&lvi,sizeof(lvi));
		lvi.mask		= LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
		lvi.state		= 0;
		lvi.stateMask	= 0;
		lvi.iItem		= dwIndex;
		lvi.iImage		= 0;
		lvi.iSubItem	= 0;
		/////////////////////////////////////////////////////////////////////////
		// 获取DLL名称
		/////////////////////////////////////////////////////////////////////////
		ZeroMemory(szText, sizeof(szText));
		dwTmpRva = iid.Name;
		RvaToOffset(dwTmpRva, dwTmpOffset);
		SetFilePointer(g_hFile, dwTmpOffset, 0, FILE_BEGIN);
		for (i = 0; ; ++i)
		{
			ReadFile(g_hFile, szBuffer, 1, &dwTmp, NULL);
			if (szBuffer[0] == '\0')
			{
				szText[i] = '\0';
				break;
			}
			szText[i] = szBuffer[0];
		}
		// 插入数据
		lvi.pszText		= szText;
		lvi.cchTextMax	= lstrlen(lvi.pszText) + 1;
		ListView_InsertItem(hListDll, &lvi);
		/////////////////////////////////////////////////////////////////////////
		// 获取OriginalFirstThunk的RVA
		/////////////////////////////////////////////////////////////////////////
		wsprintf(szText, szFormat, iid.OriginalFirstThunk);
		ListView_SetItemText(hListDll, dwIndex, 1, szText);
		/////////////////////////////////////////////////////////////////////////
		// 获取时间日期标志
		/////////////////////////////////////////////////////////////////////////
		wsprintf(szText, szFormat, iid.TimeDateStamp);
		ListView_SetItemText(hListDll, dwIndex, 2, szText);
		/////////////////////////////////////////////////////////////////////////
		// 获取ForwarderChain
		/////////////////////////////////////////////////////////////////////////
		wsprintf(szText, szFormat, iid.ForwarderChain);
		ListView_SetItemText(hListDll, dwIndex, 3, szText);
		/////////////////////////////////////////////////////////////////////////
		// 获取名称
		/////////////////////////////////////////////////////////////////////////
		wsprintf(szText, szFormat, iid.Name);
		ListView_SetItemText(hListDll, dwIndex, 4, szText);
		/////////////////////////////////////////////////////////////////////////
		// 获取FirstThunk
		/////////////////////////////////////////////////////////////////////////
		wsprintf(szText, szFormat, iid.FirstThunk);
		ListView_SetItemText(hListDll, dwIndex, 5, szText);

		// 重置文件指针
		++dwIndex;
		SetFilePointer(g_hFile, 
			dwOffset + dwIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR), 
			0, 
			FILE_BEGIN);
	}
}

// 解析从DLL导入的函数
void GetFuntionInfo(HWND& hList, DWORD dwIidIndex)
{
	if (g_hFile == NULL)
	{
		return ;
	}

	LVITEM			lvi;
	DWORD			i;
	TCHAR			szText[256];
	char			szBuffer[4];
	TCHAR			szFormat[] = TEXT("%08X");

	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_NT_HEADERS		ntHeader;
	IMAGE_DATA_DIRECTORY	dataDir;
	IMAGE_DATA_DIRECTORY	emptyDir;
	IMAGE_IMPORT_DESCRIPTOR	iid;
	IMAGE_THUNK_DATA		itd;
	IMAGE_THUNK_DATA		emptyItd;
	IMAGE_IMPORT_BY_NAME	iibn;

	DWORD			dwTmp;
	DWORD			dwStartRva;
	DWORD			dwOffset;
	DWORD			dwIndex;
	// 临时变量
	DWORD			dwTmpRva;
	DWORD			dwTmpOffset;

	// 设置文件偏移
	SetFilePointer(g_hFile, 0, 0, FILE_BEGIN);
	// 读取IMAGE_DOS_HEADER
	ReadFile(g_hFile, &dosHeader, sizeof(dosHeader),
		&dwTmp, NULL);
	// 设置文件偏移
	SetFilePointer(g_hFile, dosHeader.e_lfanew, 0, FILE_BEGIN);
	// 读取IMAGE_NT_HEADERS
	ReadFile(g_hFile, &ntHeader, sizeof(ntHeader), &dwTmp, NULL);
	// 数据目录表
	dataDir = ntHeader.OptionalHeader.DataDirectory[1];

	ZeroMemory(&emptyDir, sizeof(emptyDir));
	// 如果输出表为空
	if (!memcmp(&dataDir, &emptyDir, sizeof(dataDir)))
	{
		return ;
	}

	// 获取输入表RVA
	dwStartRva = dataDir.VirtualAddress;
	// 将RVA转化为偏移地址
	RvaToOffset(dwStartRva, dwOffset);
	// 计算文件偏移值
	dwOffset = dwOffset + dwIidIndex * (sizeof(IMAGE_IMPORT_DESCRIPTOR));
	// 设置文件偏移
	SetFilePointer(g_hFile, dwOffset, 0, FILE_BEGIN);

	// 读取IID
	ReadFile(g_hFile,
		&iid,
		sizeof(iid),
		&dwTmp,
		NULL);
	// 更新文件偏移值
	dwTmpRva = iid.OriginalFirstThunk;
	RvaToOffset(dwTmpRva, dwTmpOffset);
	dwOffset = dwTmpOffset;
	SetFilePointer(g_hFile, dwOffset, 0, FILE_BEGIN);
	// 初始化设置
	ZeroMemory(&emptyItd, sizeof(emptyItd));
	dwIndex = 0;
	dwTmpOffset = dwOffset;
	// 清空列表视图内容
	ListView_DeleteAllItems(hList);
	// 开始读取数据
	while (1)
	{
		ReadFile(g_hFile,
			&itd,
			sizeof(itd),
			&dwTmp,
			NULL);
		if (!memcmp(&itd, &emptyItd, sizeof(itd)))
		{
			return ;
		}
		/////////////////////////////////////////////////////////////////////////
		// 插入数据
		/////////////////////////////////////////////////////////////////////////
		// DllName	OriginalFirstThunk	TimeDateStamp	ForwarderChain	Name	FirstThunk
		ZeroMemory(&lvi,sizeof(lvi));
		lvi.mask		= LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
		lvi.state		= 0;
		lvi.stateMask	= 0;
		lvi.iItem		= dwIndex;
		lvi.iImage		= 0;
		lvi.iSubItem	= 0;
		/////////////////////////////////////////////////////////////////////////
		// 获取Thunk的RVA
		/////////////////////////////////////////////////////////////////////////
		OffsetToRva(dwTmpOffset, dwTmp);
		wsprintf(szText, szFormat, dwTmp);
		lvi.pszText		= szText;
		lvi.cchTextMax	= lstrlen(lvi.pszText) + 1;
		ListView_InsertItem(hList, &lvi);
		/////////////////////////////////////////////////////////////////////////
		// 获取Thunk的Offset
		/////////////////////////////////////////////////////////////////////////
		wsprintf(szText, szFormat, dwTmpOffset);
		ListView_SetItemText(hList, dwIndex, 1, szText);
		/////////////////////////////////////////////////////////////////////////
		// 获取Thunk的值
		/////////////////////////////////////////////////////////////////////////
		wsprintf(szText, szFormat, itd.u1.ForwarderString);
		ListView_SetItemText(hList, dwIndex, 2, szText);
		/////////////////////////////////////////////////////////////////////////
		// 获取Hint
		/////////////////////////////////////////////////////////////////////////
		dwTmpRva = itd.u1.AddressOfData;
		// 判断是序号还是字符串
		if ((dwTmpRva & IMAGE_ORDINAL_FLAG32) == 0)
		{
			RvaToOffset(dwTmpRva, dwOffset);
			// 设置文件偏移
			SetFilePointer(g_hFile, 
				dwOffset, 
				0, 
				FILE_BEGIN);
			// 读取IMAGE_IMPORT_BY_NAME
			ReadFile(g_hFile,
				&iibn,
				sizeof(iibn),
				&dwTmp,
				NULL);
			wsprintf(szText, TEXT("%04X"), iibn.Hint);
			ListView_SetItemText(hList, dwIndex, 3, szText);
			/////////////////////////////////////////////////////////////////////////
			// 获取DLL名称
			/////////////////////////////////////////////////////////////////////////
			ZeroMemory(szText, sizeof(szText));
			// 结构体对齐使得iibn大小为4
			// 前两个字节为HINT
			// 后两个字节为函数名称的前两个字符
			szText[0] = ((BYTE *)&iibn)[2];
			szText[1] = ((BYTE *)&iibn)[3];
			for (i = 2; ; ++i)
			{
				ReadFile(g_hFile, szBuffer, 1, &dwTmp, NULL);
				if (szBuffer[0] == '\0')
				{
					szText[i] = '\0';
					break;
				}
				szText[i] = szBuffer[0];
			}
			// 插入数据
			lvi.pszText		= szText;
			lvi.cchTextMax	= lstrlen(lvi.pszText) + 1;
			ListView_SetItemText(hList, dwIndex, 4, szText);
		}
		else
		{
			dwTmpRva &= ~IMAGE_ORDINAL_FLAG32;
			ListView_SetItemText(hList, dwIndex, 3, TEXT("序号"));
			wsprintf(szText, TEXT("%04X"), dwTmpRva);
			ListView_SetItemText(hList, dwIndex, 4, szText);
		}
		////////////////////////////////////////////////////////////////////
		// 重置文件指针
		++dwIndex;
		dwTmpOffset += sizeof(DWORD);
		SetFilePointer(g_hFile, 
			dwTmpOffset, 
			0, 
			FILE_BEGIN);
	}
}

BOOL CALLBACK IatDlgProc(HWND hwndDlg, 
						   UINT uMsg, 
						   WPARAM wParam, 
						   LPARAM lParam
						   )
{
	static HWND		hListDll;
	static HWND		hListCall;
	LV_COLUMN		lvc;
	DWORD			i;
	TCHAR			lpColNames[6][32]	= {	TEXT("DllName"), TEXT("OriginalFirstThunk"), 
											TEXT("TimeDateStamp"), TEXT("ForwarderChain"), 
											TEXT("Name"), TEXT("FirstThunk")};
	TCHAR			lpColFunNames[5][32]	= {	TEXT("Thunk RVA"), TEXT("Thunk Offset"), 
											TEXT("Thunk Value"), TEXT("Hint"), 
											TEXT("Function")};
	DWORD			dwColWidths[]	= {100, 100, 100, 100, 75, 75};
	DWORD			dwColFunWidths[]	= {90, 90, 90, 90, 190};
	switch (uMsg)
	{
		//lResult = SendMessage(
		//	// returns LRESULT in lResult
		//	(HWND) hWndControl,      
		//	// handle to destination control
		//	(UINT) WM_NOTIFY,      // message ID
		//	(WPARAM) wParam,      // = (WPARAM) (int) idCtrl;
		//	(LPARAM) lParam      // = (LPARAM) (LPNMHDR) pnmh; );  
	case WM_NOTIFY:
		switch (((LPNMHDR)lParam)->code)
		{
		case NM_CLICK:
			if (((LPNMHDR)lParam)->idFrom == IDC_LIST_IAT_DLL)
			{
				// 消息响应
				NM_LISTVIEW*	pNMListView = (NM_LISTVIEW*)lParam;
				/////////////////////////////////////////////////////
				// 获取函数详细参数
				/////////////////////////////////////////////////////
				GetFuntionInfo(hListCall, 
					pNMListView->iItem);
				// 返回
				return TRUE;
			}
		default:
			break;
		}
		return FALSE;

	case WM_INITDIALOG:
		/////////////////////////////////////////////////////////////////////
		// 初始化控件
		/////////////////////////////////////////////////////////////////////
		hListDll = GetDlgItem(hwndDlg, IDC_LIST_IAT_DLL);
		// 设置列表视图风格		
		// 行选中 + 网格
		ListView_SetExtendedListViewStyle(hListDll, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvc.iImage = 1;
		lvc.fmt = LVCFMT_LEFT;

		// 插入表头部分
		for (i = 0; i < 6; ++i)
		{
			lvc.pszText		= lpColNames[i];
			lvc.cx			= dwColWidths[i];
			lvc.iSubItem	= i;
			if (ListView_InsertColumn(hListDll, i, &lvc) == -1)
			{
				return 0;
			}
		}
		/////////////////////////////////////////////////////////////////////
		// 解析IMAGE_IMPORT_DESCRIPTOR
		/////////////////////////////////////////////////////////////////////
		ParseIID(hListDll);
		/////////////////////////////////////////////////////////////////////
		// 初始化控件
		/////////////////////////////////////////////////////////////////////
		hListCall = GetDlgItem(hwndDlg, IDC_LIST_IAT_CALL);
		// 设置列表视图风格		
		// 行选中 + 网格
		ListView_SetExtendedListViewStyle(hListCall, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvc.iImage = 1;
		lvc.fmt = LVCFMT_LEFT;

		// 插入表头部分
		for (i = 0; i < 5; ++i)
		{
			lvc.pszText		= lpColFunNames[i];
			lvc.cx			= dwColFunWidths[i];
			lvc.iSubItem	= i;
			if (ListView_InsertColumn(hListCall, i, &lvc) == -1)
			{
				return 0;
			}
		}
		return TRUE;

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;

	default:
		break;
	}
	return FALSE;
}

void GetProcessList(HWND& hListProcess)
{
	HANDLE				hSnapshot;
	PROCESSENTRY32		pe32  = {0};
	BOOL				bHasNext = FALSE;
	LVITEM				lvi;
	DWORD				i;
	TCHAR				szText[256];

	hSnapshot = CreateToolhelp32Snapshot(
					TH32CS_SNAPPROCESS,	// 建立进程快照
					0);					// 忽略
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		MessageBox(hListProcess, TEXT("创建进程快照失败！"),
			TEXT("Tip"), MB_ICONERROR);
		return ;
	}

	// 清空列表视图内容
	ListView_DeleteAllItems(hListProcess);
	
	ZeroMemory(&pe32, sizeof(PROCESSENTRY32));
	pe32.dwSize = sizeof(PROCESSENTRY32);
	bHasNext = Process32First(hSnapshot, &pe32);
	i = 0;
	while (bHasNext)
	{
		/////////////////////////////////////////////////////////////////////////
		// 插入数据
		/////////////////////////////////////////////////////////////////////////
		ZeroMemory(&lvi,sizeof(lvi));
		lvi.mask		= LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
		lvi.state		= 0;
		lvi.stateMask	= 0;
		lvi.iItem		= i;
		lvi.iImage		= 0;
		lvi.iSubItem	= 0;

		HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(
									TH32CS_SNAPMODULE,
									pe32.th32ProcessID);
		
		// 当PID为0时创建成功，但是0意味着当前进程
		// 所以要做一个特别判断
		if (hModuleSnapshot != INVALID_HANDLE_VALUE 
			&& pe32.th32ProcessID != 0)
		{
			MODULEENTRY32 me32 = {0};
			me32.dwSize = sizeof(MODULEENTRY32);
			Module32First(hModuleSnapshot, &me32);
			/////////////////////////////////////////////////////////////////////////
			// 获取进程路径
			/////////////////////////////////////////////////////////////////////////
			lvi.pszText		= me32.szExePath;
			lvi.cchTextMax	= lstrlen(lvi.pszText) + 1;
			ListView_InsertItem(hListProcess, &lvi);
			/////////////////////////////////////////////////////////////////////////
			// 获取进程PID
			/////////////////////////////////////////////////////////////////////////
			wsprintf(szText, TEXT("%d"), pe32.th32ProcessID);
			ListView_SetItemText(hListProcess, i, 1, szText);
			/////////////////////////////////////////////////////////////////////////
			// 获取进程镜像基址
			/////////////////////////////////////////////////////////////////////////
			wsprintf(szText, TEXT("%08X"), me32.modBaseAddr);
			ListView_SetItemText(hListProcess, i, 2, szText);
			/////////////////////////////////////////////////////////////////////////
			// 获取进程镜像大小
			/////////////////////////////////////////////////////////////////////////
			wsprintf(szText, TEXT("%08X"), me32.modBaseSize);
			ListView_SetItemText(hListProcess, i, 3, szText);

			CloseHandle(hModuleSnapshot);
		}
		else
		{
			//TCHAR szTmp[256];
			//wsprintf(szTmp, TEXT("%d"), GetLastError());
			//MessageBox(NULL, szTmp, szTmp, MB_OK);
			////////////////////////////////////////////////////////////////////////

			lvi.pszText		= pe32.szExeFile;
			lvi.cchTextMax	= lstrlen(lvi.pszText) + 1;
			ListView_InsertItem(hListProcess, &lvi);

			wsprintf(szText, TEXT("%d"), pe32.th32ProcessID);
			ListView_SetItemText(hListProcess, i, 1, szText);

			lstrcpy(szText, TEXT("Error"));
			ListView_SetItemText(hListProcess, i, 2, szText);

			lstrcpy(szText, TEXT("Error"));
			ListView_SetItemText(hListProcess, i, 3, szText);

		}
		/////////////////////////////////////////////////////////////////////////
		pe32.dwSize = sizeof(PROCESSENTRY32);
		bHasNext = Process32Next(hSnapshot, &pe32);
		++i;
	}
	CloseHandle(hSnapshot);
}

void GetModuleList(HWND& hListModule, 
				   DWORD pid)
{
	HANDLE				hSnapshot;
	BOOL				bHasNext = FALSE;
	LVITEM				lvi;
	DWORD				i;
	TCHAR				szText[256];

	// 清空列表视图内容
	ListView_DeleteAllItems(hListModule);

	// 当PID为0时创建成功，但是0意味着当前进程
	// 所以要做一个特别判断
	if (pid == 0)
	{
		return ;
	}

	hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,	// 建立Module快照
		pid);				// PID

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		wsprintf(szText, TEXT("创建模块快照失败！(错误代码: %d)"), GetLastError());
		MessageBox(hListModule, szText,
			TEXT("Tip"), MB_ICONERROR);
		return ;
	}

	MODULEENTRY32 me32 = {0};
	me32.dwSize = sizeof(MODULEENTRY32);
	bHasNext = Module32First(hSnapshot, &me32);
	i = 0;
	while (bHasNext)
	{
		/////////////////////////////////////////////////////////////////////////
		// 插入数据
		/////////////////////////////////////////////////////////////////////////
		ZeroMemory(&lvi,sizeof(lvi));
		lvi.mask		= LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
		lvi.state		= 0;
		lvi.stateMask	= 0;
		lvi.iItem		= i;
		lvi.iImage		= 0;
		lvi.iSubItem	= 0;

			
		/////////////////////////////////////////////////////////////////////////
		// 获取模块路径
		/////////////////////////////////////////////////////////////////////////
		lvi.pszText		= me32.szExePath;
		lvi.cchTextMax	= lstrlen(lvi.pszText) + 1;
		ListView_InsertItem(hListModule, &lvi);
		/////////////////////////////////////////////////////////////////////////
		// 获取进程镜像基址
		/////////////////////////////////////////////////////////////////////////
		wsprintf(szText, TEXT("%08X"), me32.modBaseAddr);
		ListView_SetItemText(hListModule, i, 1, szText);
		/////////////////////////////////////////////////////////////////////////
		// 获取进程镜像大小
		/////////////////////////////////////////////////////////////////////////
		wsprintf(szText, TEXT("%08X"), me32.modBaseSize);
		ListView_SetItemText(hListModule, i, 2, szText);
		/////////////////////////////////////////////////////////////////////////
		me32.dwSize = sizeof(MODULEENTRY32);
		bHasNext = Module32Next(hSnapshot, &me32);
		++i;
	}
	CloseHandle(hSnapshot);
}

// 提升进程权限，能够打开一些系统进程
// 但是对于安全类软件的进程仍然打不开
BOOL EnableDebugPrivilege()
{
	HANDLE hToken = NULL;
	BOOL bRst = OpenProcessToken(
		GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (!bRst)
		return FALSE;

	TOKEN_PRIVILEGES tknPri = {0};
	tknPri.PrivilegeCount = 1;
	bRst = LookupPrivilegeValue(
		NULL, SE_DEBUG_NAME, &tknPri.Privileges[0].Luid);
	if (!bRst)
	{
		CloseHandle(hToken);
		return FALSE;
	}

	tknPri.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	bRst = AdjustTokenPrivileges(
		hToken, FALSE, &tknPri, 
		sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (!bRst)
	{
		CloseHandle(hToken);
		return FALSE;
	}

	DWORD dwRst = GetLastError();
	if (ERROR_SUCCESS != dwRst)
	{
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}


BOOL CALLBACK TaskMgrDlgProc(HWND hwndDlg, 
						   UINT uMsg, 
						   WPARAM wParam, 
						   LPARAM lParam
						   )
{
	static HWND		hListProcess;
	static HWND		hListModule;
	LV_COLUMN		lvc;
	DWORD			i;
	TCHAR			lpColNames[4][32]	= {	TEXT("进程路径"), TEXT("PID"), 
											TEXT("镜像基址"), TEXT("镜像大小")};
	TCHAR			lpColMNames[3][32]	= {	TEXT("模块路径"), 
											TEXT("镜像基址"), TEXT("镜像大小")};
	DWORD			dwColWidths[]	= {300, 80, 80, 80};
	DWORD			dwColMWidths[]	= {380, 80, 80};
	DWORD			dwPid;
	TCHAR			szText[32];

	switch (uMsg)
	{
	case WM_INITDIALOG:
		if(!EnableDebugPrivilege())
			MessageBox(hwndDlg, TEXT("提升进程权限失败！"),
				TEXT("注意"), MB_ICONWARNING);
		/////////////////////////////////////////////////////////////////////
		// 初始化控件
		/////////////////////////////////////////////////////////////////////
		hListProcess = GetDlgItem(hwndDlg, IDC_LIST_TASKMGR_PROCESS);
		// 设置列表视图风格		
		// 行选中 + 网格
		ListView_SetExtendedListViewStyle(hListProcess, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvc.iImage = 1;
		lvc.fmt = LVCFMT_LEFT;

		// 插入表头部分
		for (i = 0; i < 4; ++i)
		{
			lvc.pszText		= lpColNames[i];
			lvc.cx			= dwColWidths[i];
			lvc.iSubItem	= i;
			if (ListView_InsertColumn(hListProcess, i, &lvc) == -1)
			{
				return 0;
			}
		}
		/////////////////////////////////////////////////////////////////////
		// 初始化控件
		/////////////////////////////////////////////////////////////////////
		hListModule = GetDlgItem(hwndDlg, IDC_LIST_TASKMGR_MODULE);
		// 设置列表视图风格		
		// 行选中 + 网格
		ListView_SetExtendedListViewStyle(hListModule, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvc.iImage = 1;
		lvc.fmt = LVCFMT_LEFT;

		// 插入表头部分
		for (i = 0; i < 3; ++i)
		{
			lvc.pszText		= lpColMNames[i];
			lvc.cx			= dwColMWidths[i];
			lvc.iSubItem	= i;
			if (ListView_InsertColumn(hListModule, i, &lvc) == -1)
			{
				return 0;
			}
		}
		/////////////////////////////////////////////////////////////////////
		// 获取进程列表
		/////////////////////////////////////////////////////////////////////
		GetProcessList(hListProcess);

		return TRUE;

	case WM_NOTIFY:
		switch (((LPNMHDR)lParam)->code)
		{
		case NM_CLICK:
			if (((LPNMHDR)lParam)->idFrom == IDC_LIST_TASKMGR_PROCESS)
			{
				// 消息响应
				NM_LISTVIEW*	pNMListView = (NM_LISTVIEW*)lParam;
				/////////////////////////////////////////////////////
				// 获取函数详细参数
				/////////////////////////////////////////////////////
				ListView_GetItemText(hListProcess,
					pNMListView->iItem,
					1,
					szText,
					sizeof(szText));
				//MessageBox(NULL, szText, szText, MB_OK);
				dwPid = 0;
				for (i = 0; i < lstrlen(szText); ++i)
				{
					dwPid *= 10;
					dwPid += szText[i] - '0';
				}
				GetModuleList(hListModule, 
					dwPid);
				// 返回
				return TRUE;
			}
		default:
			break;
		}
		return FALSE;

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;

	default:
		break;
	}
	return FALSE;
}

// 解析输出表
void ParseEat(HWND& hWnd, HWND& hList)
{
	// 判断文件句柄是否有效
	if (g_hFile == NULL || g_hFile == INVALID_HANDLE_VALUE)
	{
		return ;
	}

	LVITEM			lvi;
	DWORD			i;
	TCHAR			szText[256];
	char			szBuffer[4];
	TCHAR			szFormat[] = TEXT("%08X");

	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_NT_HEADERS		ntHeader;
	IMAGE_DATA_DIRECTORY	dataDir;
	IMAGE_DATA_DIRECTORY	emptyDir;
	IMAGE_EXPORT_DIRECTORY	ied;

	DWORD			dwTmp;
	DWORD			dwStartRva;
	DWORD			dwOffset;
	DWORD			dwIndex;
	// 临时变量
	DWORD			dwTmpRva;
	DWORD			dwTmpOffset;

	// 设置文件偏移
	SetFilePointer(g_hFile, 0, 0, FILE_BEGIN);
	// 读取IMAGE_DOS_HEADER
	ReadFile(g_hFile, &dosHeader, sizeof(dosHeader),
		&dwTmp, NULL);
	// 设置文件偏移
	SetFilePointer(g_hFile, dosHeader.e_lfanew, 0, FILE_BEGIN);
	// 读取IMAGE_NT_HEADERS
	ReadFile(g_hFile, &ntHeader, sizeof(ntHeader), &dwTmp, NULL);
	// 数据目录表
	dataDir = ntHeader.OptionalHeader.DataDirectory[0];
	ZeroMemory(&emptyDir, sizeof(emptyDir));
	// 如果输出表为空
	if (!memcmp(&dataDir, &emptyDir, sizeof(dataDir)))
	{
		return ;
	}
	// 获取输出表RVA
	dwStartRva = dataDir.VirtualAddress;
	// 将RVA转化为偏移地址
	RvaToOffset(dwStartRva, dwOffset);
	// 设置文件偏移
	SetFilePointer(g_hFile, dwOffset, 0, FILE_BEGIN);

	// 读取IMAGE_EXPORT_DIRECTORY
	ReadFile(g_hFile,
		&ied,
		sizeof(ied),
		&dwTmp,
		0);
	//////////////////////////////////////////////////////////////////////////////
	// 填充文本框数据
	//////////////////////////////////////////////////////////////////////////////
	// 输出表偏移
	wsprintf(szText, szFormat, dwOffset);
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_EATOFFSET, szText);
	// 特征值
	wsprintf(szText, szFormat, ied.Characteristics);
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_CHARACTER, szText);
	// 基址
	wsprintf(szText, szFormat, ied.Base);
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_BASE, szText);
	// 名称RVA
	wsprintf(szText, szFormat, ied.Name);
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_NAME, szText);
	// 名称字符串
	RvaToOffset(ied.Name, dwTmpOffset);
	SetFilePointer(g_hFile, dwTmpOffset, 0, FILE_BEGIN);
	for (i = 0; ; ++i)
	{
		ReadFile(g_hFile, szBuffer, 1, &dwTmp, NULL);
		if (szBuffer[0] == '\0')
		{
			szText[i] = '\0';
			break;
		}
		szText[i] = szBuffer[0];
	}
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_DLLNAME, szText);
	// 函数数量
	wsprintf(szText, szFormat, ied.NumberOfFunctions);
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_FUNNUM, szText);
	// 函数名数量
	wsprintf(szText, szFormat, ied.NumberOfNames);
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_FUNNAMENUM, szText);
	// 函数地址
	wsprintf(szText, szFormat, ied.AddressOfFunctions);
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_FUNADDR, szText);
	// 函数名地址
	wsprintf(szText, szFormat, ied.AddressOfNames);
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_FUNNAMEADDR, szText);
	// 函数序号地址
	wsprintf(szText, szFormat, ied.AddressOfNameOrdinals);
	SetDlgItemText(hWnd, IDC_EDIT_EATDLG_ORDERADDR, szText);

	//////////////////////////////////////////////////////////////////////////////
	// 解析导出函数名
	//////////////////////////////////////////////////////////////////////////////
	dwIndex = 0;
	DWORD dwAddressOfFunctions;
	DWORD dwFunctionsRva;
	DWORD dwFunctionsOffset;
	DWORD dwFunctionsIndex;
	DWORD dwFunNameRva;
	DWORD dwFunNameOffset;
	DWORD j;
	DWORD dwAddressOfNameOrdinalsOffset;
	WORD  wIndex;
	RvaToOffset(ied.AddressOfFunctions, dwAddressOfFunctions);
	for (dwIndex = 0; dwIndex < ied.NumberOfFunctions; ++dwIndex)
	{
		// 插入序号
		dwFunctionsIndex = ied.Base + dwIndex;
		wsprintf(szText, TEXT("%04X"), dwFunctionsIndex);
		ZeroMemory(&lvi,sizeof(lvi));
		lvi.mask		= LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
		lvi.state		= 0;
		lvi.stateMask	= 0;
		lvi.iItem		= dwIndex;
		lvi.iImage		= 0;
		lvi.iSubItem	= 0;
		lvi.pszText		= szText;
		lvi.cchTextMax	= lstrlen(lvi.pszText) + 1;
		ListView_InsertItem(hList, &lvi);
		// 插入RVA
		SetFilePointer(g_hFile, dwAddressOfFunctions + dwIndex*4, 0, FILE_BEGIN);
		ReadFile(g_hFile, &dwFunctionsRva, sizeof(DWORD), &dwTmp, NULL);
		wsprintf(szText, szFormat, dwFunctionsRva);
		ListView_SetItemText(hList, dwIndex, 1, szText);
		// 插入Offset
		RvaToOffset(dwFunctionsRva, dwFunctionsOffset);
		wsprintf(szText, szFormat, dwFunctionsOffset);
		ListView_SetItemText(hList, dwIndex, 2, szText);
		// 判断是否是字符串名字导出
		RvaToOffset(ied.AddressOfNameOrdinals, dwAddressOfNameOrdinalsOffset);
		SetFilePointer(g_hFile, dwAddressOfNameOrdinalsOffset, 0, FILE_BEGIN);
		for (j = 0; j < ied.NumberOfNames; ++j)
		{
			ReadFile(g_hFile, &wIndex, sizeof(WORD), &dwTmp, NULL);
			if (dwFunctionsIndex == wIndex + ied.Base)
			{
				break;
			}
		}
		if (j != ied.NumberOfNames)
		{
			RvaToOffset(ied.AddressOfNames, dwFunNameOffset);
			SetFilePointer(g_hFile, dwFunNameOffset + j*4, 0, FILE_BEGIN);
			ReadFile(g_hFile, &dwFunNameRva, sizeof(DWORD), &dwTmp, NULL);
			RvaToOffset(dwFunNameRva, dwFunNameOffset);
			SetFilePointer(g_hFile, dwFunNameOffset, 0, FILE_BEGIN);

			for (i = 0; ; ++i)
			{
				ReadFile(g_hFile, szBuffer, 1, &dwTmp, NULL);
				if (szBuffer[0] == '\0')
				{
					szText[i] = '\0';
					break;
				}
				szText[i] = szBuffer[0];
			}
			ListView_SetItemText(hList, dwIndex, 3, szText);
		}
		else
		{
			ListView_SetItemText(hList, dwIndex, 3, TEXT("序号导出"));
		}
	}
}

BOOL CALLBACK EatDlgProc(HWND hwndDlg, 
							 UINT uMsg, 
							 WPARAM wParam, 
							 LPARAM lParam
							 )
{
	static HWND		hListCall;
	LV_COLUMN		lvc;
	DWORD			i;
	TCHAR			lpColNames[4][32]	= {	TEXT("序号"), TEXT("RVA"), 
											TEXT("偏移"), TEXT("函数名")};
	DWORD			dwColWidths[]	= {100, 100, 100, 275};
	DWORD			dwEdit;
	switch (uMsg)
	{
	case WM_INITDIALOG:
		/////////////////////////////////////////////////////////////////////
		// 初始化控件
		/////////////////////////////////////////////////////////////////////
		hListCall = GetDlgItem(hwndDlg, IDC_LIST_EAT);
		// 设置列表视图风格		
		// 行选中 + 网格
		ListView_SetExtendedListViewStyle(hListCall, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvc.iImage = 1;
		lvc.fmt = LVCFMT_LEFT;

		// 插入表头部分
		for (i = 0; i < 4; ++i)
		{
			lvc.pszText		= lpColNames[i];
			lvc.cx			= dwColWidths[i];
			lvc.iSubItem	= i;
			if (ListView_InsertColumn(hListCall, i, &lvc) == -1)
			{
				return 0;
			}
		}
		/////////////////////////////////////////////////////////////////////
		// 将编辑框设置为只读属性
		/////////////////////////////////////////////////////////////////////
		for (dwEdit = IDC_EDIT_EATDLG_EATOFFSET;
			dwEdit <= IDC_EDIT_EATDLG_FUNNAMEADDR;
			++dwEdit)
		{
			SendMessage(GetDlgItem(hwndDlg, dwEdit), EM_SETREADONLY, TRUE, 0);
		}
		/////////////////////////////////////////////////////////////////////
		// 解析输出表
		/////////////////////////////////////////////////////////////////////
		ParseEat(hwndDlg, hListCall);

		return TRUE;

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;

	default:
		break;
	}
	return FALSE;
}


BOOL CALLBACK DialogProc(HWND hwndDlg, 
						 UINT uMsg, 
						 WPARAM wParam, 
						 LPARAM lParam
						 )
{
	static HANDLE	hFile;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		g_hWnd = hwndDlg;
		SetCtrlStyles();
		return TRUE;

	case WM_CLOSE:
		if (hFile != NULL)
		{
			CloseHandle(hFile);
		}
		DestroyWindow(hwndDlg);
		PostQuitMessage(0);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BTN_OPENFILE:
			if(!GetPeFilePath(szFileName))
				return TRUE;
			// 得到一个新文件
			if (hFile != NULL)
			{
				CloseHandle(hFile);
			}
			// 打开文件
			hFile = CreateFile(szFileName,
						GENERIC_READ | GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_ARCHIVE,
						NULL);
			// 判断文件是否成功打开
			if (hFile == INVALID_HANDLE_VALUE)
			{
				MessageBox(hwndDlg, TEXT("无法打开选定的文件！"),
					TEXT("提示信息"), MB_ICONERROR);
				EmptyCtrlValues();
				return FALSE;
			}
			// 保存全局句柄
			g_hFile = hFile;
			// 读取基本信息
			SetCtrlValues(hFile);
			return TRUE;

		case IDC_BTN_OK:
			SendMessage(hwndDlg, WM_CLOSE, 0, 0);
			return TRUE;

		case IDC_BTN_ABOUT:
			DialogBoxParam(g_hInstance,
				MAKEINTRESOURCE(IDD_DLG_ABOUT),
				hwndDlg,
				AboutDlgProc,
				0);
			return TRUE;

		case IDC_BTN_DATETIME:
			DialogBoxParam(g_hInstance,
				MAKEINTRESOURCE(IDD_DLG_TIME),
				hwndDlg,
				TimeDlgProc,
				0);
			return TRUE;

		case IDC_BTN_ADDRESS:
			DialogBoxParam(g_hInstance,
				MAKEINTRESOURCE(IDD_DLG_ADDRESS),
				hwndDlg,
				AddressDlgProc,
				0);
			return TRUE;

		case IDC_BTN_SECTION:
			DialogBoxParam(g_hInstance,
				MAKEINTRESOURCE(IDD_DLG_SECTION),
				hwndDlg,
				SectionDlgProc,
				0);
			return TRUE;

		case IDC_BTN_IAT:
			DialogBoxParam(g_hInstance,
				MAKEINTRESOURCE(IDD_DLG_IAT),
				hwndDlg,
				IatDlgProc,
				0);
			return TRUE;

		case IDC_BTN_TASKMGR:
			DialogBoxParam(g_hInstance,
				MAKEINTRESOURCE(IDD_DLG_TASKMGR),
				hwndDlg,
				TaskMgrDlgProc,
				0);
			return TRUE;

		// 这几个功能懒得去实现了
		case IDC_BTN_SUBSYSTEM:
		case IDC_BTN_CHARACTER:
			UnImplementationTips();
			return TRUE;
		
		// 输出表的解析
		case IDC_BTN_EXPORT:
			DialogBoxParam(g_hInstance,
				MAKEINTRESOURCE(IDD_DLG_EXPORT),
				hwndDlg,
				EatDlgProc,
				0);
			return TRUE;
		
		default:
			break;
		}

	default:
		break;
	}
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// 主函数
//////////////////////////////////////////////////////////////////////
int WINAPI WinMain(HINSTANCE hInstance,
				   HINSTANCE hPrevInstance,
				   LPSTR lpCmdLine,
				   int nShowCmd)
{
	g_hInstance = hInstance;

	DialogBox(hInstance,
		MAKEINTRESOURCE(IDD_DLG_MAIN),
		NULL,
		DialogProc);

	return 0;
}
