
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.386
		.model flat, stdcall
		option casemap :none
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; Include 引入頭文件
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
include		C:\masm32\include\windows.inc
include		C:\masm32\include\user32.inc
includelib	C:\masm32\lib\user32.lib
include		C:\masm32\include\kernel32.inc

includelib	C:\masm32\lib\kernel32.lib
include		C:\masm32\include\comdlg32.inc
includelib	C:\masm32\lib\comdlg32.lib
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; Equ 		常數定義
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
ICO_MAIN	equ	1000
DLG_MAIN	equ	1000
IDC_INFO	equ	1001
IDM_MAIN	equ	2000
IDM_OPEN	equ	2001
IDM_EXIT	equ	2002
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 數據段
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.data?
hInstance	dd	?
hRichEdit	dd	?
hWinMain	dd	?
hWinEdit	dd	?
szFileName	db	MAX_PATH dup (?)

		.const
szDllEdit	db	'RichEd20.dll',0;使用系統默認選擇文件對話框
szClassEdit	db	'RichEdit20A',0
szFont		db	'宋體',0
szExtPe		db	'PE Files',0,'*.exe;*.dll;*.scr;*.fon;*.drv',0
		db	'All Files(*.*)',0,'*.*',0,0
szErr		db	'文件格式錯誤',0
szErrFormat	db	'這個文件不是pe格式的文件',0
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 代碼段
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		.code
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_AppendInfo	proc	_lpsz
		local	@stCR:CHARRANGE

		pushad
		invoke	GetWindowTextLength,hWinEdit
		mov	@stCR.cpMin,eax
		mov	@stCR.cpMax,eax
		invoke	SendMessage,hWinEdit,EM_EXSETSEL,0,addr @stCR
		invoke	SendMessage,hWinEdit,EM_REPLACESEL,FALSE,_lpsz
		popad
		ret

_AppendInfo	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
include		_ProcessPeFile.asm
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_Init		proc
		local	@stCf:CHARFORMAT

		invoke	GetDlgItem,hWinMain,IDC_INFO
		mov	hWinEdit,eax
		invoke	LoadIcon,hInstance,ICO_MAIN
		invoke	SendMessage,hWinMain,WM_SETICON,ICON_BIG,eax
		invoke	SendMessage,hWinEdit,EM_SETTEXTMODE,TM_PLAINTEXT,0
		invoke	RtlZeroMemory,addr @stCf,sizeof @stCf
		mov	@stCf.cbSize,sizeof @stCf
		mov	@stCf.yHeight,9 * 20
		mov	@stCf.dwMask,CFM_FACE or CFM_SIZE or CFM_BOLD
		invoke	lstrcpy,addr @stCf.szFaceName,addr szFont
		invoke	SendMessage,hWinEdit,EM_SETCHARFORMAT,0,addr @stCf
		invoke	SendMessage,hWinEdit,EM_EXLIMITTEXT,0,-1
		ret

_Init		endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 錯誤 Handler(這段代碼有待理解)
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_Handler	proc	_lpExceptionRecord,_lpSEH,_lpContext,_lpDispatcherContext

		pushad
		mov	esi,_lpExceptionRecord
		mov	edi,_lpContext
		assume	esi:ptr EXCEPTION_RECORD,edi:ptr CONTEXT
		mov	eax,_lpSEH
		push	[eax + 0ch]
		pop	[edi].regEbp
		push	[eax + 8]
		pop	[edi].regEip
		push	eax
		pop	[edi].regEsp
		assume	esi:nothing,edi:nothing
		popad
		mov	eax,ExceptionContinueExecution
		ret

_Handler	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_OpenFile	proc
		local	@stOF:OPENFILENAME
		local	@hFile,@dwFileSize,@hMapFile,@lpMemory

		invoke	RtlZeroMemory,addr @stOF,sizeof @stOF
		mov	@stOF.lStructSize,sizeof @stOF
		push	hWinMain
		pop	@stOF.hwndOwner
		mov	@stOF.lpstrFilter,offset szExtPe
		mov	@stOF.lpstrFile,offset szFileName
		mov	@stOF.nMaxFile,MAX_PATH
		mov	@stOF.Flags,OFN_PATHMUSTEXIST or OFN_FILEMUSTEXIST
		invoke	GetOpenFileName,addr @stOF
		.if	! eax
			jmp	@F
		.endif
;********************************************************************
; 打開文件並建立文件 Mapping
;********************************************************************
		invoke	CreateFile,addr szFileName,GENERIC_READ,FILE_SHARE_READ or \
			FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,NULL
		.if	eax !=	INVALID_HANDLE_VALUE
			mov	@hFile,eax
			invoke	GetFileSize,eax,NULL
			mov	@dwFileSize,eax
			.if	eax
				invoke	CreateFileMapping,@hFile,NULL,PAGE_READONLY,0,0,NULL
				.if	eax
					mov	@hMapFile,eax
					invoke	MapViewOfFile,eax,FILE_MAP_READ,0,0,0
					.if	eax
						mov	@lpMemory,eax
;********************************************************************
; 創建用於錯誤處理的的 SEH 結構(WINDOWS的意外處理)
;********************************************************************
						assume	fs:nothing
						push	ebp
						push	offset _ErrFormat
						push	offset _Handler
						push	fs:[0]
						mov	fs:[0],esp
;********************************************************************
; 檢查pe文件是否有效
;********************************************************************
						mov	esi,@lpMemory
						assume	esi:ptr IMAGE_DOS_HEADER
						.if	[esi].e_magic != IMAGE_DOS_SIGNATURE
							jmp	_ErrFormat
						.endif
						add	esi,[esi].e_lfanew
						assume	esi:ptr IMAGE_NT_HEADERS
						.if	[esi].Signature != IMAGE_NT_SIGNATURE
							jmp	_ErrFormat
						.endif
						invoke	_ProcessPeFile,@lpMemory,esi,@dwFileSize
						jmp	_ErrorExit
_ErrFormat:
						invoke	MessageBox,hWinMain,addr szErrFormat,NULL,MB_OK
_ErrorExit:
						pop	fs:[0]
						add	esp,0ch
						invoke	UnmapViewOfFile,@lpMemory
					.endif
					invoke	CloseHandle,@hMapFile
				.endif
				invoke	CloseHandle,@hFile
			.endif
		.endif
@@:
		ret

_OpenFile	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_ProcDlgMain	proc	uses ebx edi esi hWnd,wMsg,wParam,lParam

		mov	eax,wMsg
		.if	eax == WM_CLOSE
			invoke	EndDialog,hWnd,NULL
		.elseif	eax == WM_INITDIALOG
			push	hWnd
			pop	hWinMain
			call	_Init
		.elseif	eax == WM_COMMAND
			mov	eax,wParam
			.if	ax ==	IDM_OPEN
				call	_OpenFile
			.elseif	ax ==	IDM_EXIT
				invoke	EndDialog,hWnd,NULL
			.endif
		.else
			mov	eax,FALSE
			ret
		.endif
		mov	eax,TRUE
		ret

_ProcDlgMain	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
start:
		invoke	LoadLibrary,offset szDllEdit
		mov	hRichEdit,eax
		invoke	GetModuleHandle,NULL
		mov	hInstance,eax
		invoke	DialogBoxParam,hInstance,DLG_MAIN,NULL,offset _ProcDlgMain,NULL
		invoke	FreeLibrary,hRichEdit
		invoke	ExitProcess,NULL
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		end	start
