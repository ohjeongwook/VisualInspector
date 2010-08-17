#pragma warning(disable:4100)
#pragma warning(disable:4244)
#pragma warning(disable:4127)

#define USE_ONE_SHOT_BREAKPOINT 1

int DebugLevel=0;

#include <windows.h>
#include <stdio.h>

#include "VisualInspector.h"

#include <list>
#include <hash_set>
#include <hash_map>
#include <string>

using namespace std;
using namespace stdext;


#include "XGetopt.h"
#include "StringToArgumentList.h"

void DumpHex(unsigned char *Buffer,int BufferLen)
{
	char LineBuffer[256];
	memset(LineBuffer,' ',50);
	LineBuffer[50]=0;
	char ascii[17];
	ascii[16]=0;
	int i;

	for(i=0;i<BufferLen;i++)
	{
		sprintf(LineBuffer+(i%16)*3,"%0.2X ",Buffer[i]);
		if(isprint(Buffer[i]))
			ascii[i%16]=Buffer[i];
		else
			ascii[i%16]='.';

		if(i%16==15) 
		{
			sprintf(LineBuffer+48,"  %s",ascii);
			dprintf("%s\r\n",LineBuffer);
		}
	}

	if(i%16!=0)
	{
		memset(LineBuffer+(i%16)*3,' ',(16-(i%16))*3);
		ascii[i%16]=0;
		sprintf(LineBuffer+48,"  %s",ascii);
		dprintf("%s\r\n",LineBuffer);
	}
}

char **ParseDiasm(char *DisasmBuffer,ULONG DisassemblySize,int &ReturnCount)
{
	//7724a6bc 8955c0          mov     dword ptr [ebp-40h],edx ss:002b:ffffffc0=????????
	//Address+Bytes+Op+Operands separated by ','

	DisasmBuffer=_strdup(DisasmBuffer);

	//Remove \r\n at the end of string
	if(DisassemblySize>2 && (DisasmBuffer[DisassemblySize-2]=='\r' || DisasmBuffer[DisassemblySize-2]=='\n'))
	{
		DisasmBuffer[DisassemblySize-2]=NULL;
		if(DisassemblySize>3 && (DisasmBuffer[DisassemblySize-3]=='\r' || DisasmBuffer[DisassemblySize-3]=='\n'))
		{
			DisasmBuffer[DisassemblySize-3]=NULL;
		}
	}

	int PartCount=0;
	const int MaximumPartsCount=4;
	char **Parts=(char **)malloc(sizeof(char *)*MaximumPartsCount);
	int TracePart=TRUE;
	for(ULONG i=0;i<DisassemblySize;i++)
	{
		if(DisasmBuffer[i]==' ')
		{
			if(!TracePart)
			{
				DisasmBuffer[i]=NULL;
				TracePart=TRUE;
			}
		}else if(TracePart)
		{
			Parts[PartCount]=DisasmBuffer+i;
			PartCount++;
			if(MaximumPartsCount<=PartCount)
				break;
			TracePart=FALSE;
		}
	}
	//Remove ss:00... ds:00...
	if(PartCount==MaximumPartsCount)
	{
		char *Operands=Parts[3];
		for(DWORD i=0;i<strlen(Operands);i++)
		{
			if(!_strnicmp(Operands+i," ss:00",6) ||!_strnicmp(Operands+i," ds:00",6) ||!_strnicmp(Operands+i," fs:00",6) || !_strnicmp(Operands+i," {",2))
			{
				Operands[i]=NULL;
				break; 
			}
		}
	}

	if(PartCount==MaximumPartsCount && DebugLevel>3)
	{
		/*
		7724a76a 83450c18        add     dword ptr [ebp+0Ch],18h ss:002b:0000000c=????????

		0 7724a76a
		1 83450c18
		2 add
		3 dword ptr [ebp+0Ch],18h ss:002b:0000000c=????????
		*/
		for(int i=0;i<PartCount;i++)
		{
			dprintf("%d %s\n",i,Parts[i]);
		}
	}
	for(int i=0;i<PartCount;i++)
	{
		Parts[i]=_strdup(Parts[i]);
	}
	free(DisasmBuffer);
	ReturnCount=PartCount;
	return Parts;
}

unsigned char HexToChar(char *Hex)
{
	unsigned char ReturnValue=0;
	for(int i=0;Hex[i] && i<2;i++)
	{
		int CurrentInt=-1;
		char c=Hex[i];
		if('0' <= c && c <='9')
		{
			CurrentInt=c-'0';
		}else if('a' <= c && c <='f')
		{
			CurrentInt=c-'a'+10;
		}else if('A' <= c && c <='F')
		{
			CurrentInt=c-'A'+10;
		}
		if(CurrentInt>=0)
			ReturnValue=ReturnValue*16+CurrentInt;
	}
	return ReturnValue;
}

unsigned char *HexToBytes(char *HexBytes,int *pLen)
{
	int StrLen=strlen(HexBytes);
	*pLen=StrLen/2;
	unsigned char *Bytes=(unsigned char *)malloc(*pLen);
	if(DebugLevel>4)
		dprintf("Length=%d StrLen=%d\n",*pLen,StrLen);
	if(Bytes)
	{
		for(int i=0;i<StrLen;i+=2)
		{
			if(*pLen-1-i/2<0)
				break;
			Bytes[*pLen-1-i/2]=HexToChar(HexBytes+i);
			if(DebugLevel>4)
				dprintf("\tBytes[%d]=0x%.2x\n",*pLen-1-i/2,Bytes[*pLen-1-i/2]);
		}
	}
	return Bytes;
}

void GetJumpAddress(char *Operands,ULONG64 *pJmpAddress)
{
	DWORD i;
	*pJmpAddress=0;
	for(i=0;i<strlen(Operands)-1;i++)
	{
		if(Operands[i]=='(')
		{
			char *StartOfAddress=Operands+i+1;
			int AddressStrLen=0;
			for(;i<strlen(Operands);i++)
			{
				if(Operands[i]==')')
				{
					//We are at the end of the string
					char *NumberBuffer=(char *)malloc(AddressStrLen);
					memcpy(NumberBuffer,StartOfAddress,AddressStrLen-1);
					NumberBuffer[AddressStrLen-1]=0;

					int Len;
					unsigned char *Bytes=HexToBytes(NumberBuffer,&Len);
					if(Bytes)
					{
						*pJmpAddress=(ULONG64)*(DWORD *)Bytes;
						if(DebugLevel>3)
						{
							dprintf("Operands=%s\n",Operands);
							dprintf("%s=%X\n",NumberBuffer,*pJmpAddress);
							dprintf("%p: 0x%.2x%.2x%.2x%.2x`%.2x%.2x%.2x%.2x\n",
								*pJmpAddress,
								(short)((*pJmpAddress>>56)& 0xff),
								(short)((*pJmpAddress>>48)& 0xff),
								(short)((*pJmpAddress>>44)& 0xff),
								(short)((*pJmpAddress>>36)& 0xff),
								(short)((*pJmpAddress>>28)& 0xff),
								(short)((*pJmpAddress>>20)& 0xff),
								(short)((*pJmpAddress>>12)& 0xff),
								(short)((*pJmpAddress>>8)& 0xff),
								(short)((*pJmpAddress)& 0xff));
						}
						free(Bytes);
					}
					break;
				}
				AddressStrLen++;
			}
			break;
		}
	}
}

typedef struct _INSTR_
{
	string Address;
	string Bytes;
	string OpCode;
	string Operands;
} INSTR,*PINSTR;

typedef struct _BASIC_BLOCK_INFO_
{
	ULONG64 StartAddress;
	ULONG64 EndAddress;
	list <INSTR> Instructions;
	list <ULONG64> Addresses;
} BASIC_BLOCK_INFO,*PBASIC_BLOCK_INFO;

void RetrieveBasicBlockInfoHashMap(ULONG64 Address,hash_map <ULONG64,PBASIC_BLOCK_INFO> &BasicBlockInfoHashMap,BOOL DoRetrieveLines)
{
	list <ULONG64> BasicBlockAddresses;
	list <ULONG64>::iterator BasicBlockAddressesIterator;

	BOOL MaskAddress=FALSE;
	if((Address&0xffffffff00000000)==0xffffffff00000000)
	{
		MaskAddress=TRUE;
	}

	BasicBlockAddresses.push_back(Address);	

	PBASIC_BLOCK_INFO BasicBlockInfo=new BASIC_BLOCK_INFO;
	BasicBlockInfoHashMap.insert(pair<ULONG64,PBASIC_BLOCK_INFO>(Address,BasicBlockInfo));

	for(BasicBlockAddressesIterator=BasicBlockAddresses.begin();
		BasicBlockAddressesIterator!=BasicBlockAddresses.end();
		BasicBlockAddressesIterator++)
	{
		ULONG64 CurrentAddress=*BasicBlockAddressesIterator;
		ULONG64 StartAddress=CurrentAddress;
		hash_map <ULONG64,PBASIC_BLOCK_INFO>::iterator BasicBlockInfoHashMapIterator=BasicBlockInfoHashMap.find(CurrentAddress);
		if(BasicBlockInfoHashMapIterator==BasicBlockInfoHashMap.end())
		{
			continue;
		}
		BasicBlockInfoHashMapIterator->second->StartAddress=CurrentAddress;
		if(DebugLevel>2)
			dprintf("Analyzing Basic Block %p\n",CurrentAddress);
		ULONG64 EndOffset=CurrentAddress;
		while(CurrentAddress<StartAddress+50000)
		{
			char DisasmBuffer[1024]={0,};
			ULONG DisassemblySize;			

			if(g_ExtControl->Disassemble(CurrentAddress,
				DEBUG_DISASM_EFFECTIVE_ADDRESS,
				DisasmBuffer,
				sizeof(DisasmBuffer)-1,
				&DisassemblySize,
				&EndOffset)==S_OK)
			{
				if(DebugLevel>3)
					dprintf("Disassembly: %s\n",DisasmBuffer);


				int PartCount;
				char **Parts=ParseDiasm(DisasmBuffer,DisassemblySize,PartCount);

				if(Parts && PartCount>3)
				{
					char *Address=Parts[0];
					char *Bytes=Parts[1];
					char *OpCode=Parts[2];
					char *Operands=Parts[3];
					if(DebugLevel>3)
						dprintf("%s/%s/%s/%s\n",Address,Bytes,OpCode,Operands);

					if(DoRetrieveLines)
					{
						INSTR Instruction;
						Instruction.Address=Address;
						Instruction.Bytes=Bytes;
						Instruction.OpCode=OpCode;
						Instruction.Operands=Operands;
					
						BasicBlockInfoHashMapIterator->second->Instructions.push_back(Instruction);
					}
					//CFG change is the condition for breaking
					if(!_strnicmp(OpCode,"ret",3))
						break;
					if(OpCode[0]=='j')
					{
						//jae     ntdll!RtlpAllocateHeap+0x8f (77259ded)  [br=1]
						//ntdll!RtlpAllocateHeap+0xb73 (77259e3b) [br=0]
						if(DebugLevel>3)
							dprintf("%s\n",DisasmBuffer);
						ULONG64 JmpAddress;
						GetJumpAddress(Operands,&JmpAddress);
						if(DebugLevel>2)
							dprintf("\tBranches=%p,%p\n",EndOffset,JmpAddress);

						if(MaskAddress)
						{
							if((EndOffset|0x00000000ffffffff)==0x00000000ffffffff)
								EndOffset|=0xffffffff00000000;
							if((JmpAddress|0x00000000ffffffff)==0x00000000ffffffff)
								JmpAddress|=0xffffffff00000000;
						}

						if(_stricmp(OpCode,"jmp"))
						{
							BasicBlockInfoHashMapIterator->second->Addresses.push_back(EndOffset);
							if(BasicBlockInfoHashMap.find(EndOffset)==BasicBlockInfoHashMap.end())
							{
								BasicBlockAddresses.push_back(EndOffset);
								PBASIC_BLOCK_INFO BasicBlockInfo=new BASIC_BLOCK_INFO;
								if(DebugLevel>3)
								{
									dprintf("\tAdding EndOffset=%p\n",EndOffset);
									DumpHex((unsigned char *)&EndOffset,sizeof(EndOffset));
								}

								BasicBlockInfoHashMap.insert(pair<ULONG64,PBASIC_BLOCK_INFO>(EndOffset,BasicBlockInfo));
							}
						}

						if(EndOffset!=JmpAddress)
						{
							BasicBlockInfoHashMapIterator->second->Addresses.push_back(JmpAddress);
							if(BasicBlockInfoHashMap.find(JmpAddress)==BasicBlockInfoHashMap.end())
							{
								BasicBlockAddresses.push_back(JmpAddress);
								PBASIC_BLOCK_INFO BasicBlockInfo=new BASIC_BLOCK_INFO;
								if(DebugLevel>3)
								{
									dprintf("\tAdding JmpAddress=%p\n",JmpAddress);
									DumpHex((unsigned char *)&JmpAddress,sizeof(JmpAddress));
								}
								BasicBlockInfoHashMap.insert(pair<ULONG64,PBASIC_BLOCK_INFO>(JmpAddress,BasicBlockInfo));
							}
						}

						break;
					}else if(!_stricmp(OpCode,"call"))
					{
						//01002a0c/ff1594120001/call/dword ptr [notepad!_imp__DispatchMessageW (01001294)]
						//0100297b/e8e51b0000/call/notepad!NPInit (01004565)
						//01002a19/ffd7/call/edi
						//01002a44/ff55fc/call/dword ptr [ebp-4]   
						if(DebugLevel>2)
							dprintf("%s %s %s %s\n",Address,Bytes,OpCode,Operands);
					}
				}
				if(Parts)
					for(int i=0;i<PartCount;i++)
					{
						if(Parts[i])
							free(Parts[i]);
					}
				else
					break;

				CurrentAddress=EndOffset;
			}else
			{
				break;
			}
		}
		BasicBlockInfoHashMapIterator->second->EndAddress=EndOffset;
	}

	int EndAddressCollisionFound=TRUE;
	while(EndAddressCollisionFound)
	{
		EndAddressCollisionFound=FALSE;
		hash_map <ULONG64,PBASIC_BLOCK_INFO> EndAddressHashMap;
		hash_map <ULONG64,PBASIC_BLOCK_INFO>::iterator EndAddressHashMapIterator;
		hash_map <ULONG64,PBASIC_BLOCK_INFO>::iterator BasicBlockInfoHashMapIterator;
		for(BasicBlockInfoHashMapIterator=BasicBlockInfoHashMap.begin();
			BasicBlockInfoHashMapIterator!=BasicBlockInfoHashMap.end();
			BasicBlockInfoHashMapIterator++)
		{
			PBASIC_BLOCK_INFO CurrentBB=BasicBlockInfoHashMapIterator->second;
			EndAddressHashMapIterator=EndAddressHashMap.find(BasicBlockInfoHashMapIterator->second->EndAddress);
			if(EndAddressHashMapIterator!=EndAddressHashMap.end())
			{
				PBASIC_BLOCK_INFO FoundBB=EndAddressHashMapIterator->second;

				PBASIC_BLOCK_INFO FirstBB=NULL;
				PBASIC_BLOCK_INFO SecondBB=NULL;
				if(CurrentBB->Instructions.size()<FoundBB->Instructions.size())
				{
					FirstBB=FoundBB;
					SecondBB=CurrentBB;
				}else
				{
					FirstBB=CurrentBB;
					SecondBB=FoundBB;
				}
				if(DebugLevel>3)
					dprintf("%p-%p -> %p-%p\n",
						FirstBB->StartAddress,
						FirstBB->EndAddress,
						SecondBB->StartAddress,
						SecondBB->EndAddress
						);
				//Process FirstBB
				int InstructCountToRetain=FirstBB->Instructions.size()-SecondBB->Instructions.size();
				if(DebugLevel>3)
					dprintf("Retain %d(%d-%d) instructions\n",InstructCountToRetain,FirstBB->Instructions.size(),SecondBB->Instructions.size());

				int CurrentCount=0;
				for(list <INSTR>::iterator InstructionsIterator=FirstBB->Instructions.begin();
					InstructionsIterator!=FirstBB->Instructions.end();
					InstructionsIterator++)
				{
					CurrentCount++;
					if(CurrentCount>InstructCountToRetain)
					{
						FirstBB->Instructions.erase(InstructionsIterator,FirstBB->Instructions.end());
						break;
					}
				}
				FirstBB->EndAddress=SecondBB->StartAddress;
				FirstBB->Addresses.clear();
				FirstBB->Addresses.push_back(SecondBB->StartAddress);

				if(DebugLevel>3)
					dprintf("Splitted %p -> %p\n",FirstBB->StartAddress,SecondBB->StartAddress);

				//Reconfigure EndAddressHashMap
				EndAddressHashMap.erase(EndAddressHashMapIterator);
				EndAddressHashMap.insert(pair<ULONG64,PBASIC_BLOCK_INFO>(FirstBB->EndAddress,FirstBB));
				EndAddressHashMap.insert(pair<ULONG64,PBASIC_BLOCK_INFO>(SecondBB->EndAddress,SecondBB));
				EndAddressCollisionFound=TRUE;
			}else
			{
				EndAddressHashMap.insert(pair<ULONG64,PBASIC_BLOCK_INFO>(BasicBlockInfoHashMapIterator->second->EndAddress,BasicBlockInfoHashMapIterator->second));
			}
		}
	}
}

void WriteToFile(HANDLE hFile,const char *format,...)
{
	va_list args;
	va_start(args,format);
	char Contents[1024]={0,};
	_vsnprintf(Contents,sizeof(Contents)/sizeof(char),format,args);
	va_end(args);

	if(hFile!=INVALID_HANDLE_VALUE) 
	{
		DWORD dwBytesWritten;
		BOOL fSuccess=WriteFile(hFile,
			Contents,
			strlen(Contents),
			&dwBytesWritten,
			NULL); 
		if(!fSuccess) 
		{
			dprintf("WriteFile failed with error %u.\n",GetLastError());
		}
	}else
	{
	}
}

int OutputDOT(hash_map <ULONG64,PBASIC_BLOCK_INFO> &BasicBlockInfoHashMap,list <ULONG64> *pBreakPointLog,char *OutFilname)
{

	hash_map <ULONG64,ULONG64> VisitedBB;

	if(pBreakPointLog)
	{
		for(list <ULONG64>::iterator BreakPointLogIterator=pBreakPointLog->begin();
			BreakPointLogIterator!=pBreakPointLog->end();
			BreakPointLogIterator++)
		{
			list <ULONG64>::iterator NextBreakPointLogIterator=BreakPointLogIterator;
			NextBreakPointLogIterator++;
			if(NextBreakPointLogIterator!=pBreakPointLog->end())
			{
				VisitedBB.insert(pair<ULONG64,ULONG64>(*BreakPointLogIterator,*NextBreakPointLogIterator));
			}else
			{
				VisitedBB.insert(pair<ULONG64,ULONG64>(*BreakPointLogIterator,0));
			}
		}
	}

	//Draw Graph
	HANDLE hFile=CreateFile(OutFilname, // file to create
		GENERIC_WRITE, // open for writing
		0, // do not share
		NULL, // default security
		CREATE_ALWAYS, // overwrite existing
		FILE_ATTRIBUTE_NORMAL | // normal file
		NULL, // asynchronous I/O
		NULL); // no attr. template
	if(hFile==INVALID_HANDLE_VALUE) 
	{ 
		dprintf("Could not open file (error %d)\n", GetLastError());
		return 0;
	}
	//WriteToFile(hFile,"digraph g { \n");
	WriteToFile(hFile,"digraph g { graph[rankdir = \"TB\"];\r\nnode [fontname=\"Helvetica\",fontsize=9,style=filled] \n");

	hash_map <ULONG64,PBASIC_BLOCK_INFO>::iterator BasicBlockInfoHashMapIterator;
	for(BasicBlockInfoHashMapIterator=BasicBlockInfoHashMap.begin();
		BasicBlockInfoHashMapIterator!=BasicBlockInfoHashMap.end();
		BasicBlockInfoHashMapIterator++)
	{
		ULONG64 Address=BasicBlockInfoHashMapIterator->first;
		WriteToFile(hFile,"\"Node%I64x\" [\n",Address);
		WriteToFile(hFile,"\tlabel=\"{%X",Address);
		int first_entry=TRUE;
		for(list <INSTR>::iterator InstructionsIter=BasicBlockInfoHashMapIterator->second->Instructions.begin();
			InstructionsIter!=BasicBlockInfoHashMapIterator->second->Instructions.end();
			InstructionsIter++)
		{
			if(first_entry)
			{
				WriteToFile(hFile,"|");
				first_entry=FALSE;
			}
			string DisasmLine=(*InstructionsIter).OpCode;
			DisasmLine+=" ";
			DisasmLine+=(*InstructionsIter).Operands;
			//Escape <,>...
			for(std::string::iterator iter=DisasmLine.begin();
				iter!=DisasmLine.end();
				iter++)
			{
				if(*iter=='<' || *iter=='>')
				{
					iter=DisasmLine.insert(iter,'\\');
					iter++;
				}
			}

			WriteToFile(hFile,"%s\\r\\n",DisasmLine.c_str());
		}
		WriteToFile(hFile,"}\"\n");
		WriteToFile(hFile,"\tshape=\"record\"\n");
		if(VisitedBB.find(Address)!=VisitedBB.end())
		{
			//Visited node
			WriteToFile(hFile,"\tfillcolor=\"red\",color=\"white\",fontcolor=\"white\"\n");
		}
		WriteToFile(hFile,"];\n");
	}

	for(BasicBlockInfoHashMapIterator=BasicBlockInfoHashMap.begin();
		BasicBlockInfoHashMapIterator!=BasicBlockInfoHashMap.end();
		BasicBlockInfoHashMapIterator++)
	{
		ULONG64 Address=BasicBlockInfoHashMapIterator->first;
		for(list <ULONG64>::iterator AddressesIter=BasicBlockInfoHashMapIterator->second->Addresses.begin();
			AddressesIter!=BasicBlockInfoHashMapIterator->second->Addresses.end();
			AddressesIter++)
		{
			WriteToFile(hFile,"Node%I64x -> Node%I64x",Address,*AddressesIter);
			hash_map <ULONG64,ULONG64>::iterator VisitedBBIterator=VisitedBB.find(Address);
			if(VisitedBBIterator!=VisitedBB.end() && VisitedBBIterator->second==*AddressesIter)
			{
				WriteToFile(hFile," [color=\"red\"];");
			}
			WriteToFile(hFile,"\n");			
		}
	}
	WriteToFile(hFile,"};\n");
	CloseHandle(hFile);

	return 1;
}

int ConvertUsingDOT(char *DotFilename, char *Format="png", char *PNGFilename=NULL, 
					const char *GraphvizDotExe="C:\\Program Files\\Graphviz2.26\\bin\\dot.exe")
{
	BOOL ShowOutput=FALSE;
	int ret=FALSE;
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;
	BOOL PNGFilenameAllocated=FALSE;

	if(!PNGFilename)
	{
		PNGFilenameAllocated=TRUE;
		//replace .dot -> .png
		PNGFilename=_strdup(DotFilename);
		PNGFilename[strlen(PNGFilename)-4]='.';
		memcpy(PNGFilename+strlen(PNGFilename)-3,Format,3);
	}

	//dot -Tpng -otrace.png trace.dot
	char szCmdline[1024]={0,};
	
	_snprintf(szCmdline,sizeof(szCmdline)-1,"\"%s\" -T%s -o%s %s", GraphvizDotExe, Format, PNGFilename, DotFilename);
	dprintf("%s: Executing [%s] \n",__FUNCTION__,szCmdline);

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = sizeof StartupInfo ; //Only compulsory field
	if(CreateProcess(
		NULL,
		szCmdline,      // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&StartupInfo,            // Pointer to STARTUPINFO structure
		&ProcessInformation)           // Pointer to PROCESS_INFORMATION structure
	)
	{
		ret=TRUE;
		WaitForSingleObject(ProcessInformation.hProcess,INFINITE);

		::CloseHandle(ProcessInformation.hThread);
		::CloseHandle(ProcessInformation.hProcess);
	}

	if(ShowOutput)
	{
		_snprintf(szCmdline,sizeof(szCmdline)-1,"cmd.exe /c start %s",PNGFilename);
		dprintf("%s: Executing [%s] \n",__FUNCTION__,szCmdline);
		if(CreateProcess(
			NULL,
			szCmdline,      // Command line
			NULL,           // Process handle not inheritable
			NULL,           // Thread handle not inheritable
			FALSE,          // Set handle inheritance to FALSE
			0,              // No creation flags
			NULL,           // Use parent's environment block
			NULL,           // Use parent's starting directory 
			&StartupInfo,            // Pointer to STARTUPINFO structure
			&ProcessInformation)           // Pointer to PROCESS_INFORMATION structure
		)
		{
			ret=TRUE;
			::CloseHandle(ProcessInformation.hThread);
			::CloseHandle(ProcessInformation.hProcess);
		}
	}


	if(PNGFilenameAllocated)
		free(PNGFilename);
	return ret;
}

/*
  This gets called (by DebugExtensionNotify whentarget is halted and is accessible
*/
HRESULT NotifyOnTargetAccessible(PDEBUG_CONTROL Control)
{
	dprintf("Extension dll detected a break");
	if (Connected) {
		dprintf(" connected to ");
		switch (TargetMachine) {
		case IMAGE_FILE_MACHINE_I386:
			dprintf("X86");
			break;
		case IMAGE_FILE_MACHINE_IA64:
			dprintf("IA64");
			break;
		default:
			dprintf("Other");
			break;
		}
	}
	dprintf("\n");

	//
	// show the top frame and execute dv to dump the locals here and return
	//
	Control->Execute(DEBUG_OUTCTL_ALL_CLIENTS |
					DEBUG_OUTCTL_OVERRIDE_MASK |
					DEBUG_OUTCTL_NOT_LOGGED,
					".frame",// Command to be executed
					DEBUG_EXECUTE_DEFAULT );
	Control->Execute(DEBUG_OUTCTL_ALL_CLIENTS |
					DEBUG_OUTCTL_OVERRIDE_MASK |
					DEBUG_OUTCTL_NOT_LOGGED,
					"dv",// Command to be executed
					DEBUG_EXECUTE_DEFAULT );
	return S_OK;
}

/*
typedef struct _FIELD_INFO {
    PUCHAR  fName;
    PUCHAR  printName;
    ULONG  size;
    ULONG  fOptions;
    ULONG64  address;
    union {
        PVOID  fieldCallBack;
        PVOID  pBuffer;
    };
    ULONG  TypeId;
    ULONG  FieldOffset;
    ULONG  BufferSize;
    struct _BitField {
        USHORT  Position;
        USHORT  Size;
    }  BitField;
    ULONG  fPointer:2;
    ULONG  fArray:1;
    ULONG  fStruct:1;
    ULONG  fConstant:1;
    ULONG  Reserved:27;
} FIELD_INFO, *PFIELD_INFO;
*/
typedef struct _DT_INFO_
{
	string Name;
	list <FIELD_INFO> Fields;
} DT_INFO;

typedef struct _STRUCTURE_INFO_
{
	ULONG64 Base;
	ULONG64 CurrentID;
	list <ULONG64> TypeIDs;
	hash_set <ULONG64> TypeIDChecked;
	list <FIELD_INFO> Fields;
	BOOL IsFirstCallback;
} STRUCTURE_INFO;

ULONG WDBGAPI DumpFieldCallback(struct _FIELD_INFO *pField,PVOID UserContext)
{
	STRUCTURE_INFO *pStructureInfo=(STRUCTURE_INFO *)UserContext;
	if(pStructureInfo)
	{
		if(pStructureInfo->IsFirstCallback)
			pStructureInfo->IsFirstCallback=FALSE;
		else
		{
			if(DebugLevel>2)
			{
				char NameBuffer[1024];
				g_ExtSymbols->GetTypeName(
					pStructureInfo->Base,
					pField->TypeId,
					NameBuffer,
					sizeof(NameBuffer),
					NULL);
				if(DebugLevel>3)
					dprintf("%.2d %s(%s) %x %d TypeId=%d %s (%s)\n",
						pField->FieldOffset,
						pField->fName,
						pField->printName,
						pField->pBuffer,
						pField->size,
						pField->TypeId,
						NameBuffer,
						pField->fStruct?"Structure":"");
				dprintf("%s %s(%x)\n",pField->fName,NameBuffer,pField->TypeId);
			}
			FIELD_INFO FiledInfo;
			memcpy(&FiledInfo,pField,sizeof(FiledInfo));
			if(pField->fName)
				FiledInfo.fName=(PUCHAR)_strdup((const char *)pField->fName);
			if(pField->printName)
				FiledInfo.printName=(PUCHAR)_strdup((const char *)pField->printName);
			pStructureInfo->Fields.push_back(FiledInfo);
			if(pStructureInfo->TypeIDChecked.find(pField->TypeId)==pStructureInfo->TypeIDChecked.end() &&
				(pField->fStruct || pField->fPointer || pField->fArray)
			)
			{
				pStructureInfo->TypeIDChecked.insert(pField->TypeId);
				pStructureInfo->TypeIDs.push_back(pField->TypeId);
			}
		}
	}
	return 0;
}

char *GetPseudoName(char *NameBuffer,ULONG64 ID)
{
	int str_len=strlen(NameBuffer);
	if(str_len>1 && !_stricmp(NameBuffer+str_len-1,"*"))
	{
		NameBuffer[str_len-1]=NULL;
	}
	else if(str_len>3 && !_stricmp(NameBuffer+str_len-3,"*[]"))
	{
		NameBuffer[str_len-3]=NULL;
	}
	else if(str_len>2 && !_stricmp(NameBuffer+str_len-2,"[]"))
	{
		NameBuffer[str_len-2]=NULL;		
	}
	else if(!_stricmp(NameBuffer,"__unnamed"))
	{
		char *NewName=(char *)malloc(30);
		_snprintf(NewName,30,"Unamed%I64X",ID);
		return NewName;
	}
	return _strdup(NameBuffer);
}

HRESULT CALLBACK dt(PDEBUG_CLIENT4 Client,PCSTR args)
{
	INIT_API();

	ULONG64 Base;
	g_ExtSymbols->GetSymbolModule(args,&Base);

	ULONG TypeId;
	g_ExtSymbols->GetTypeId(Base,args,&TypeId);

	char NameBuffer[1024]={0,};

	g_ExtSymbols->GetTypeName(
		Base,
		TypeId,
		NameBuffer,
		sizeof(NameBuffer),
		NULL);
	char *PseudoName=GetPseudoName(NameBuffer,TypeId);
	if(DebugLevel>2)
	{
		dprintf("************************************************************************\n");
		dprintf("%s(%I64x)\n",PseudoName,TypeId);
	}
	STRUCTURE_INFO StructureInfo;
	StructureInfo.Base=Base;

	hash_map <ULONG64,DT_INFO> IdToDTMap;

	StructureInfo.Fields.clear();
	StructureInfo.IsFirstCallback=FALSE;
	SYM_DUMP_PARAM Sym={
       sizeof(SYM_DUMP_PARAM), //size
		(PUCHAR)NameBuffer, //sName
		DBG_DUMP_CALL_FOR_EACH|DBG_DUMP_NO_PRINT, //Options
		NULL, //addr
		NULL, //listLink
		(PVOID)&StructureInfo, //Context or pBuffer
		DumpFieldCallback, //CallbackRoutine
		0, //nFields
		NULL, //Fields
		Base,//ModBase;
		TypeId,//TypeId;
   		0,//TypeSize;
   		0,//BufferSize;
   		0,//fPointer:2;
   		0,//fArray:1;
   		0,//fStruct:1;
   		0,//fConstant:1;
   		0,//Reserved:27;
    };
	if (!Ioctl(IG_DUMP_SYMBOL_INFO,&Sym,Sym.size))
	{
		//return S_OK;
	}

	hash_map <string,ULONG64> NameToIDMap;

	DT_INFO dt_info;
	dt_info.Name=PseudoName;
	dt_info.Fields=StructureInfo.Fields;
	IdToDTMap.insert(pair<ULONG64,DT_INFO>(TypeId,dt_info));
	NameToIDMap.insert(pair<string,ULONG64>(PseudoName,TypeId));

	list <ULONG64>::iterator TypeIDsIter;
	for(TypeIDsIter=StructureInfo.TypeIDs.begin();TypeIDsIter!=StructureInfo.TypeIDs.end();TypeIDsIter++)
	{
		g_ExtSymbols->GetTypeName(
			Base,
			*TypeIDsIter,
			NameBuffer,
			sizeof(NameBuffer),
			NULL);

		char *PseudoName=GetPseudoName(NameBuffer,*TypeIDsIter);
		if(DebugLevel>2)
		{
			dprintf("************************************************************************\n");
			dprintf("%s(%I64x)\n",PseudoName,*TypeIDsIter);
		}
		StructureInfo.Fields.clear();
		StructureInfo.IsFirstCallback=TRUE;
		SYM_DUMP_PARAM Sym={
		   sizeof(SYM_DUMP_PARAM), //size
			(PUCHAR)NULL, //sName
			DBG_DUMP_CALL_FOR_EACH|DBG_DUMP_NO_PRINT, //Options
			NULL, //addr
			NULL, //listLink
			(PVOID)&StructureInfo, //Context or pBuffer
			DumpFieldCallback, //CallbackRoutine
			0, //nFields
			NULL, //Fields
			Base, //ModBase;
			*TypeIDsIter, //TypeId;
   			0, //TypeSize;
   			0, //BufferSize;
   			0, //fPointer:2;
   			0, //fArray:1;
   			0, //fStruct:1;
   			0, //fConstant:1;
   			0, //Reserved:27;
		};
		if (!Ioctl(IG_DUMP_SYMBOL_INFO,&Sym,Sym.size))
		{
		}

		if(NameToIDMap.find(PseudoName)==NameToIDMap.end())
		{
			NameToIDMap.insert(pair<string,ULONG64>(PseudoName,*TypeIDsIter));
		}
		if(StructureInfo.Fields.size()>0)
		{
			DT_INFO dt_info;
			dt_info.Name=PseudoName;
			dt_info.Fields=StructureInfo.Fields;
			IdToDTMap.insert(pair<ULONG64,DT_INFO>(*TypeIDsIter,dt_info));
		}
		free(PseudoName);
	}

	HANDLE hFile=CreateFile(TEXT("out.dot"), // file to create
		GENERIC_WRITE, // open for writing
		0, // do not share
		NULL, // default security
		CREATE_ALWAYS, // overwrite existing
		FILE_ATTRIBUTE_NORMAL | // normal file
		NULL, // asynchronous I/O
		NULL); // no attr. template
	if(hFile==INVALID_HANDLE_VALUE) 
	{ 
		dprintf("Could not open file (error %d)\n", GetLastError());
		return 0;
	}
	WriteToFile(hFile,"digraph g {graph [rankdir = \"LR\"];");
	hash_map <ULONG64,DT_INFO>::iterator IdToDTMapIter;
	list <FIELD_INFO>::iterator FieldsIter;

	hash_map <ULONG64,ULONG64> SameTypeIDMap;
	for(IdToDTMapIter=IdToDTMap.begin();
		IdToDTMapIter!=IdToDTMap.end();
		IdToDTMapIter++)
	{
		ULONG64 TypeID=IdToDTMapIter->first;
		hash_map <string,ULONG64>::iterator NameToIDMapIterator=NameToIDMap.find(IdToDTMapIter->second.Name);
		//TypeID => NameToIDMapIterator->second
		if(NameToIDMapIterator==NameToIDMap.end())
		{
			SameTypeIDMap.insert(pair<ULONG64,ULONG64>(TypeID,TypeID));
		}else
		{
			SameTypeIDMap.insert(pair<ULONG64,ULONG64>(TypeID,NameToIDMapIterator->second));
		}
		if(NameToIDMapIterator!=NameToIDMap.end() && NameToIDMapIterator->second==TypeID)
		{
			WriteToFile(hFile,"\"Node%I64x\" [\n",TypeID);
			WriteToFile(hFile,"\tlabel=\"");
			int first_entry=TRUE;
			WriteToFile(hFile,"%s",IdToDTMapIter->second.Name.c_str());
			first_entry=FALSE;
			for(FieldsIter=IdToDTMapIter->second.Fields.begin();
				FieldsIter!=IdToDTMapIter->second.Fields.end();
				FieldsIter++)
			{
				if(!first_entry)
					WriteToFile(hFile,"|");
				first_entry=FALSE;
				WriteToFile(hFile,"<%s>%s",(*FieldsIter).fName,(*FieldsIter).fName);
			}
			WriteToFile(hFile,"\"\n");
			WriteToFile(hFile,"\tshape=\"record\"\n");
			WriteToFile(hFile,"];\n");
		}
	}

	hash_set <ULONG32> CheckedIDs;

	for(IdToDTMapIter=IdToDTMap.begin();
		IdToDTMapIter!=IdToDTMap.end();
		IdToDTMapIter++)
	{
		ULONG64 TypeID=IdToDTMapIter->first;
		hash_map <ULONG64,ULONG64>::iterator SameTypeIDMapIterator;
				
		SameTypeIDMapIterator=SameTypeIDMap.find(TypeID);
		if(SameTypeIDMapIterator!=SameTypeIDMap.end())
		{
			ULONG64 SrcID=SameTypeIDMapIterator->second;
			if(CheckedIDs.find(SrcID)==CheckedIDs.end())
			{
				CheckedIDs.insert(SrcID);
				for(FieldsIter=IdToDTMapIter->second.Fields.begin();
					FieldsIter!=IdToDTMapIter->second.Fields.end();
					FieldsIter++)
				{
					if(StructureInfo.TypeIDChecked.find((*FieldsIter).TypeId)!=StructureInfo.TypeIDChecked.end())
					{
						SameTypeIDMapIterator=SameTypeIDMap.find((*FieldsIter).TypeId);
						if(SameTypeIDMapIterator!=SameTypeIDMap.end())
						{
							ULONG64 DstID=SameTypeIDMapIterator->second;

							WriteToFile(hFile,"Node%I64x:%s -> Node%x[];\n",SrcID,(*FieldsIter).fName,DstID);
						}
					}
				}
			}
		}
	}
	WriteToFile(hFile,"};\n");
	CloseHandle(hFile);
	EXIT_API();
	return S_OK;
}

char *GetPreviousDisassemble(ULONG64 DataInStack)
{
	char DisasmBuffer[1024]={0,};
	ULONG DisassemblySize;
	ULONG64 EndOffset;
	ULONG64 PreviousOffset;
	for(PreviousOffset=DataInStack-1;PreviousOffset>DataInStack-20;PreviousOffset--)
	{
		if(g_ExtControl->Disassemble(PreviousOffset,DEBUG_DISASM_EFFECTIVE_ADDRESS,DisasmBuffer,sizeof(DisasmBuffer),&DisassemblySize,&EndOffset)==S_OK)
		{
			if(EndOffset==DataInStack)
			{
				for(ULONG i=0;i<DisassemblySize;i++)
				{
					if(!_strnicmp(DisasmBuffer+i," call ",6))
					{
						return _strdup(DisasmBuffer);
					}
				}
			}
		}
	}
	return NULL;
}

HRESULT CALLBACK kb(PDEBUG_CLIENT4 Client,PCSTR args)
{
	INIT_API();

	ULONG64 StackOffset;
	g_ExtRegisters->GetStackOffset(&StackOffset);

	/*
	0:000> dt -r _TEB 7efdd000
	ntdll!_TEB
	   +0x000 NtTib            : _NT_TIB
	...
		  +0x000 ExceptionList    : Ptr32 _EXCEPTION_REGISTRATION_RECORD
		  +0x004 StackBase        : 0x00180000 
		  +0x008 StackLimit       : 0x0017d000 
	...
	+0x018 ProcessHeap      : 0x00580000
	...
	+0x090 ProcessHeaps     : 0x773624e0  -> 0x00580000 
	...
	*/
	ULONGLONG TebAddress;
	GetTebAddress(&TebAddress);

	ULONG64 StackBase;
	if(!GetFieldValue(TebAddress,"nt!_NT_TIB","StackBase",StackBase))
	{
		if(DebugLevel>3)
			dprintf("StackBase=%p",StackBase);
	}

	ULONG64 StackLimit;
	if(!GetFieldValue(TebAddress,"nt!_NT_TIB","StackLimit",StackLimit))
	{
		if(DebugLevel>3)
			dprintf("StackLimit=%p",StackLimit);
	} 

	/*
	0:000> dt _EXCEPTION_REGISTRATION_RECORD
	ntdll!_EXCEPTION_REGISTRATION_RECORD
	   +0x000 Next             : Ptr32 _EXCEPTION_REGISTRATION_RECORD
	   +0x004 Handler          : Ptr32     _EXCEPTION_DISPOSITION 
	0:000> dt _EXCEPTION_DISPOSITION 
	ntdll!_EXCEPTION_DISPOSITION
	   ExceptionContinueExecution = 0
	   ExceptionContinueSearch = 1
	   ExceptionNestedException = 2
	   ExceptionCollidedUnwind = 3
   */
	ULONG64 ExceptionList=0;
	if(!GetFieldValue(TebAddress,"nt!_NT_TIB","ExceptionList",ExceptionList))
	{
		if(DebugLevel>0)
			dprintf("ExceptionList=%p\n ",ExceptionList);
		ULONG64 CurrentExceptionList=ExceptionList;
		do
		{
			ULONG64 Handler;
			if(!GetFieldValue(CurrentExceptionList,"nt!_EXCEPTION_REGISTRATION_RECORD","Handler",Handler))
			{
				char NameBuffer[1024]={0,};
				ULONG NameSize;
				ULONG64 Displacement;
				if(g_ExtSymbols->GetNameByOffset(Handler,NameBuffer,sizeof(NameBuffer),&NameSize,&Displacement)==S_OK)
				{
				}
				if(DebugLevel>0)
					dprintf("%p %p (%s+%x)\n",CurrentExceptionList,Handler,NameBuffer,Displacement);
			}
		}while(!GetFieldValue(CurrentExceptionList,"nt!_EXCEPTION_REGISTRATION_RECORD","Next",CurrentExceptionList));

	}

	if(StackOffset>=StackLimit)
	{
		//Stack Heuristics
		hash_set <ULONG64> VisitedStackFramePointer;
		for(ULONG64 StackPointer=StackOffset;StackPointer<StackBase;StackPointer+=4)
		{
			if(DebugLevel>3)
				dprintf("%p ",StackPointer);

			ULONG64 CurrentStackFramePointer=StackPointer;
			ULONG64 DataInStack;
			list <ULONG64> StackFramePointerList;
			while(ReadPointer(CurrentStackFramePointer,&DataInStack) && CurrentStackFramePointer<DataInStack && DataInStack<=StackBase)
			{
				if(VisitedStackFramePointer.find(DataInStack)!=VisitedStackFramePointer.end())
					break;
				VisitedStackFramePointer.insert(DataInStack);
				StackFramePointerList.push_back(CurrentStackFramePointer);
				CurrentStackFramePointer=DataInStack;
			}

			if(StackFramePointerList.size()>1)
			{
				BOOL IsFirst=TRUE;
				for(list <ULONG64>::iterator StackFramePointerListIterator=StackFramePointerList.begin();
					StackFramePointerListIterator!=StackFramePointerList.end();
					StackFramePointerListIterator++
				)
				{
					CurrentStackFramePointer=*StackFramePointerListIterator;
					if(ExceptionList==CurrentStackFramePointer)
						break;
					if(IsFirst)
					{
						dprintf("=========================================================================\n");
						IsFirst=FALSE;
					}
					ULONG64 ReturnAddress;
					ReadPointer(CurrentStackFramePointer+4,&ReturnAddress);

					char NameBuffer[1024]={0,};
					ULONG NameSize;
					ULONG64 Displacement;
					if(g_ExtSymbols->GetNameByOffset(ReturnAddress,NameBuffer,sizeof(NameBuffer),&NameSize,&Displacement)==S_OK)
					{
						dprintf("%p %p %p (%s+%x)\n",CurrentStackFramePointer,DataInStack,ReturnAddress,NameBuffer,Displacement);
					}else
					{
						char *PreviousDisassemble=GetPreviousDisassemble(ReturnAddress);
						dprintf("%p %p %p -\n",CurrentStackFramePointer,DataInStack,ReturnAddress,PreviousDisassemble?PreviousDisassemble:"");
						if(PreviousDisassemble)
							free(PreviousDisassemble);
						
					}
					char *PreviousDisassemble=GetPreviousDisassemble(ReturnAddress);
					if(PreviousDisassemble)
					{
						dprintf("\t%s\n",PreviousDisassemble);
						free(PreviousDisassemble);
					}
				}
			}

		}

		//Brute Forcing
		dprintf("=Brute Forcing========================================================================\n");
		for(ULONG64 StackPointer=StackOffset;StackPointer<StackBase;StackPointer+=4)
		{
			if(DebugLevel>3)
				dprintf("%p ",StackPointer);
			ULONG64 DataInStack;
			if(ReadPointer(StackPointer,&DataInStack))
			{
				if(DebugLevel>3)
					dprintf(" %p\n",DataInStack);
				char *PreviousDisassemble=GetPreviousDisassemble(DataInStack);
				if(PreviousDisassemble)
				{
					dprintf("%p %p %s\n",StackPointer,DataInStack,PreviousDisassemble);
					free(PreviousDisassemble);
				}
			}
		}
	}

	EXIT_API();
	return S_OK;
}

HRESULT CALLBACK u(PDEBUG_CLIENT4 Client,PCSTR args)
{
	INIT_API();

	//!vs.u -o <filename> -l 30 <address>
	//-o <filename>: Output filename
	//-l : Maximum level for analysis

	int argc;
	char **argv=StringToArgumentList(args,&argc);
	char *optstring="o:l:";
	int optind=0;
	char *optarg;
	int c;

	if(DebugLevel>2)
	{
		dprintf("%s: args=[%s]\n",__FUNCTION__,args);
		for(int i=0;i<argc;i++)
		{
			dprintf("%s: argv[%d]=[%s]\n",__FUNCTION__,i,argv[i]);
		}
	}
	char *OutputFilename=NULL;
	int Level=-1;
	while((c=getopt(argc,argv,optstring,&optind,&optarg,FALSE))!=EOF)
	{
		switch(c)
		{
			case 'o':
				OutputFilename=optarg;
				break;
			case 'l':
				Level=atoi(optarg);
				break;
		}
	}
	char *AddressStr=NULL;
	if(optind<argc)
		AddressStr=argv[optind];

	if(DebugLevel>2)
		dprintf("%s: AddressStr=[%s]\n",__FUNCTION__,AddressStr);
	ULONG64 Address=GetExpression(AddressStr);

	hash_map <ULONG64,PBASIC_BLOCK_INFO> BasicBlockInfoHashMap;
	RetrieveBasicBlockInfoHashMap(Address,BasicBlockInfoHashMap,TRUE);

	if(OutputFilename)
	{
		OutputDOT(BasicBlockInfoHashMap,NULL,OutputFilename);
		ConvertUsingDOT(OutputFilename);
	}

	FreeArgumentList((const char **)argv,argc);

	EXIT_API();
	return S_OK;
}

hash_map <ULONG64,PBASIC_BLOCK_INFO> BasicBlockInfoHashMap;

typedef list <ULONG64> BREAKPOINT_LOG;
BREAKPOINT_LOG BreakPointLog;
hash_map<ULONG64,BREAKPOINT_LOG> BreakPointLogMap;
DWORD BreakPointLogSeq=0;

typedef struct _BP_INFO_
{
	IDebugBreakpoint *Bp;
	int IsPermanent;
	int ReferenceCount;
	list <ULONG64> LinkedBPs;
} BP_INFO;

hash_map <ULONG64,BP_INFO> BreakPointInformationMap;

class EventCallbacks:public DebugBaseEventCallbacks
{
private:
	char *OutputFilename;
	bool AutomaticContinue;
	int MaximumNumberOfBasicBlocksToTrace;
public:
	EventCallbacks():OutputFilename(NULL),AutomaticContinue(FALSE),MaximumNumberOfBasicBlocksToTrace(-1)
	{
	}

	~EventCallbacks()
	{
		FreeOutputFilename();
	}

	void FreeOutputFilename()
	{
		if(OutputFilename)
			free(OutputFilename);
	}

	void SetOutputFilename(const char *ParamOutputFilename)
	{
		FreeOutputFilename();
		OutputFilename=_strdup((char *)ParamOutputFilename);
	}

	void SetAutomaticContinueFlag(bool ParamAutomaticContinue)
	{
		AutomaticContinue=ParamAutomaticContinue;
	}

	void SetMaximumNumberOfBasicBlocksToTrace(int ParamMaximumNumberOfBasicBlocksToTrace)
	{
		MaximumNumberOfBasicBlocksToTrace=ParamMaximumNumberOfBasicBlocksToTrace;
	}

	STDMETHODIMP_(ULONG)AddRef(THIS)
	{
		// This class is designed to be static so
		// there's no true refcount.
		return 1;
	}

	STDMETHODIMP_(ULONG)Release(THIS)
	{
		// This class is designed to be static so
		// there's no true refcount.
		return 0;
	}

	STDMETHODIMP GetInterestMask(THIS_ OUT PULONG Mask)
	{
		if(DebugLevel>3)
			dprintf("%s: Entry\n",__FUNCTION__);
		*Mask=DEBUG_EVENT_BREAKPOINT|DEBUG_EVENT_CHANGE_DEBUGGEE_STATE;
		return S_OK;
	}

	STDMETHODIMP Breakpoint(THIS_ IN PDEBUG_BREAKPOINT Bp)
	{
		ULONG Id;

		if(DebugLevel>3)
			dprintf("%s\n",__FUNCTION__);
		if(Bp->GetId(&Id)!=S_OK)
		{
			dprintf("Failed to get breakpoint\r\n");
			return DEBUG_STATUS_BREAK;
		}

		static BOOL TraceCount=10;
		/*
		typedef struct _DEBUG_BREAKPOINT_PARAMETERS
		{
			ULONG64 Offset;
			ULONG Id;
			ULONG BreakType;
			ULONG ProcType;
			ULONG Flags;
			ULONG DataSize;
			ULONG DataAccessType;
			ULONG PassCount;
			ULONG CurrentPassCount;
			ULONG MatchThread;
			ULONG CommandSize;
			ULONG OffsetExpressionSize;
		} DEBUG_BREAKPOINT_PARAMETERS, *PDEBUG_BREAKPOINT_PARAMETERS;
		*/
		DEBUG_BREAKPOINT_PARAMETERS Params;
		Bp->GetParameters(&Params);
		ULONGLONG TebAddress;
		GetTebAddress(&TebAddress);

		hash_map <ULONG64,PBASIC_BLOCK_INFO>::iterator BasicBlockInfoHashMapIterator;
		BasicBlockInfoHashMapIterator=BasicBlockInfoHashMap.find(Params.Offset);
		if(BasicBlockInfoHashMapIterator!=BasicBlockInfoHashMap.end())
		{
			if(DebugLevel>-1)
				dprintf("Breakpoint(%x) at %I64X(TebAddress=0x%I64x)\r\n",Id,Params.Offset,TebAddress);

			hash_map<ULONG64,BREAKPOINT_LOG>::iterator BreakPointLogMapIterator=BreakPointLogMap.find(TebAddress);
			if(BreakPointLogMapIterator==BreakPointLogMap.end())
			{
				BREAKPOINT_LOG aBreakPointLog;
				BreakPointLogMap.insert(pair<ULONG64,BREAKPOINT_LOG>(TebAddress,aBreakPointLog));
				dprintf("%s: Adding first entry to teb=%p\n",__FUNCTION__,TebAddress);
				BreakPointLogMapIterator=BreakPointLogMap.find(TebAddress);
			}

			PDEBUG_CLIENT DebugClient;
			PDEBUG_CONTROL DebugControl;
			HRESULT Hr;
			if((Hr=DebugCreate(__uuidof(IDebugClient),(void **)&DebugClient))!=S_OK)
			{
				dprintf("%s: Creating DebugClient Failed\n",__FUNCTION__);
				return DEBUG_STATUS_GO;
			}
			if((Hr=DebugClient->QueryInterface(__uuidof(IDebugControl),(void **)&DebugControl))!=S_OK)
			{
				dprintf("%s: Querying DebugControl Failed\n",__FUNCTION__);
				return DEBUG_STATUS_GO;
			}

			//Take care of Current BP
			//TODO: Check BreakPointInformationMap
			//For all LinkedBPs
			//	Get BpInfo 
			hash_map <ULONG64,BP_INFO>::iterator BreakPointInformationMapIterator=BreakPointInformationMap.find(Params.Offset);
			if(BreakPointInformationMapIterator!=BreakPointInformationMap.end())
			{
				//	If BpInfo.IsPermanent==FALSE && BpInfo.ReferenceCount==0  -> Remove the breakpoint and data
				list <ULONG64> LinkedBPs=BreakPointInformationMapIterator->second.LinkedBPs;
				for(list <ULONG64>::iterator LinkedBPsIterator=LinkedBPs.begin();
					LinkedBPsIterator!=LinkedBPs.end();
					LinkedBPsIterator++)
				{
					ULONG64 BPAddress=*LinkedBPsIterator;
					hash_map <ULONG64,BP_INFO>::iterator BreakPointInformationMapIterator2=BreakPointInformationMap.find(BPAddress);
					if(BreakPointInformationMapIterator2!=BreakPointInformationMap.end())
					{
						if(BreakPointInformationMapIterator2->second.IsPermanent==FALSE)
						{
							BreakPointInformationMapIterator2->second.ReferenceCount--;
							dprintf("%s: Decreasing BP %I64x ReferenceCount=%d\n",
									__FUNCTION__,
									BPAddress,
									BreakPointInformationMapIterator2->second.ReferenceCount);
							if(BreakPointInformationMapIterator2->second.ReferenceCount==0)
							{
								 //No one is interested in the BP now
								 //Clear it!
								HRESULT Ret=DebugControl->RemoveBreakpoint(BreakPointInformationMapIterator2->second.Bp);
								dprintf("%s: Removing %p (%s)\n",__FUNCTION__,BPAddress,Ret==S_OK?"OK":"Failed");
								BreakPointInformationMap.erase(BreakPointInformationMapIterator2);
							}
						}
					}
				}
			}

			//Take care of Next BPs
#ifdef USE_ONE_SHOT_BREAKPOINT
			IDebugBreakpoint *NewBp;
			for(list <ULONG64>::iterator AddressIter=BasicBlockInfoHashMapIterator->second->Addresses.begin();
				AddressIter!=BasicBlockInfoHashMapIterator->second->Addresses.end();
				AddressIter++)
			{
				int AddBP=FALSE;
				ULONG64 Address=*AddressIter;
				//Look up BreakPointInformationMap
				BreakPointInformationMapIterator=BreakPointInformationMap.find(Address);
				if(BreakPointInformationMapIterator!=BreakPointInformationMap.end())
				{
					//Found Increase ReferenceCount
					BreakPointInformationMapIterator->second.ReferenceCount++;					
					dprintf("%s: Increasing BP %I64x ReferenceCount=%d\n",__FUNCTION__,
						Address,
						BreakPointInformationMapIterator->second.ReferenceCount);
					//TODO: BpInfo.LinkedBPs=BasicBlockInfoHashMapIterator->second->Addresses;

					for(list <ULONG64>::iterator iter=BasicBlockInfoHashMapIterator->second->Addresses.begin();
						iter!=BasicBlockInfoHashMapIterator->second->Addresses.end();
						iter++)
					{
						BreakPointInformationMapIterator->second.LinkedBPs.push_back(*iter);
					}

					if(BreakPointInformationMapIterator->second.ReferenceCount==1)
					{
						AddBP=TRUE;
					}
				}else
				{
					AddBP=TRUE;
					//Update BreakPointInformationMap
					BP_INFO BpInfo;
					BpInfo.IsPermanent=FALSE;
					BpInfo.ReferenceCount=1;
					BpInfo.LinkedBPs=BasicBlockInfoHashMapIterator->second->Addresses;
					BreakPointInformationMap.insert(pair<ULONG64,BP_INFO>(Address,BpInfo));
					BreakPointInformationMapIterator=BreakPointInformationMap.find(Address);
				}
				if(AddBP)
				{
					 if(DebugControl->AddBreakpoint(DEBUG_BREAKPOINT_CODE,DEBUG_ANY_ID,&NewBp)==S_OK && Bp)
					 {
						//Else Add New BP
						dprintf("%s: Addig BP %X\n",__FUNCTION__,Address);
						NewBp->SetOffset(Address);
						if(NewBp->AddFlags(DEBUG_BREAKPOINT_ENABLED)!=S_OK)
							dprintf("%s: Addig BP %X failed\n",__FUNCTION__,Address);
						BreakPointInformationMapIterator->second.Bp=NewBp;
					}
				}
			}
#endif
			EXT_RELEASE(DebugControl);
			EXT_RELEASE(DebugClient);

			if(BreakPointLogMapIterator!=BreakPointLogMap.end())
			{
				BREAKPOINT_LOG *pBreakPointLog=&(BreakPointLogMapIterator->second);
				pBreakPointLog->push_back(Params.Offset);
				
				if(BasicBlockInfoHashMapIterator->second->Addresses.size()==0)
				{
					for(list <ULONG64>::iterator BreakPointLogIterator=pBreakPointLog->begin();
						BreakPointLogIterator!=pBreakPointLog->end();
						BreakPointLogIterator++)
					{
						dprintf("%p\r\n",*BreakPointLogIterator);
					}
					if(OutputFilename)
					{
						char Filename[1024]={0,};
						_snprintf(Filename,sizeof(Filename)-1,OutputFilename,BreakPointLogSeq);
						BreakPointLogSeq++;
						OutputDOT(BasicBlockInfoHashMap,pBreakPointLog,Filename);
						ConvertUsingDOT(Filename);
						//Delete BreakPointLogMapIterator
						BreakPointLogMap.erase(BreakPointLogMapIterator);
					}
					if(TraceCount>0 || TraceCount==-1)
					{
						if(TraceCount>0)
							TraceCount--;
						return DEBUG_STATUS_GO;
					}
					else
					{
						if(AutomaticContinue)
						{
							return DEBUG_STATUS_GO;
						}else
						{
							return DEBUG_STATUS_BREAK;
						}
					}
				}
			}

			return DEBUG_STATUS_GO;
		}else
		{
			dprintf("Not Found Breakpoint(%x) at %I64X(thread=%x)\r\n",Id,Params.Offset,TebAddress);
		}
		return DEBUG_STATUS_BREAK;		
	}

	STDMETHOD(ChangeDebuggeeState)(
		THIS_
		__in ULONG Flags,
		__in ULONG64 Argument
		)
	{
		if(DebugLevel>3)
			dprintf("%s\n",__FUNCTION__);
		UNREFERENCED_PARAMETER(Flags);
		UNREFERENCED_PARAMETER(Argument);

		PDEBUG_CLIENT DebugClient;
		PDEBUG_CONTROL DebugControl;
		HRESULT Hr;

		if ((Hr = DebugCreate(__uuidof(IDebugClient),
							  (void **)&DebugClient)) != S_OK) {
			return Hr;
		}

		if ((Hr = DebugClient->QueryInterface(__uuidof(IDebugControl),
											  (void **)&DebugControl)) == S_OK) {
			return Hr;
		}

		EXT_RELEASE(DebugControl);
		EXT_RELEASE(DebugClient);

		return S_OK;
	}
};

static EventCallbacks g_EventCb;
static BOOL EventCallbackRegistered=FALSE;

HRESULT CALLBACK trace(PDEBUG_CLIENT4 Client,PCSTR args)
{
	INIT_API();

	//!vs.u -o <filename> -l 30 <address>
	//-o <filename>: Output filename
	//-b <number>: Maximum number of basic block to trace
	//-c: Automatic continue

	int argc;
	char **argv=StringToArgumentList(args,&argc);
	char *optstring="o:b:c";
	int optind=0;
	TCHAR *optarg;
	int c;


	if(DebugLevel>2)
	{
		dprintf("%s: args=[%s]\n",__FUNCTION__,args);
		for(int i=0;i<argc;i++)
		{
			dprintf("%s: argv[%d]=[%s]\n",__FUNCTION__,i,argv[i]);
		}
	}

	char *OutputFilename=NULL;
	int MaximumNumberOfBasicBlocksToTrace=-1;
	bool AutomaticContinue=false;
	while((c=getopt(argc,argv,optstring,&optind,&optarg,FALSE))!=EOF)
	{
		if(DebugLevel>-2)
		{
			dprintf("%s: argv[%d]=%s\n",__FUNCTION__,optind,argv[optind]);
		}
		switch(c)
		{
			case 'o':
				OutputFilename=optarg;
				break;
			case 'b':
				MaximumNumberOfBasicBlocksToTrace=atoi(optarg);
				break;
			case 'c':
				AutomaticContinue=true;
				break;
		}
	}
	char *AddressStr=NULL;
	if(optind<argc)
		AddressStr=argv[optind];

	ULONG64 Address;
	if(AddressStr)
	{
		Address=GetExpression(AddressStr);
	}else
	{
		g_ExtRegisters->GetInstructionOffset(&Address);
	}
	dprintf("%s: %X\n",__FUNCTION__,Address);

	BreakPointLogMap.clear();
	BreakPointInformationMap.clear();
	if(BasicBlockInfoHashMap.size()>0)
	{
		BasicBlockInfoHashMap.clear();
		g_ExtControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS|
						DEBUG_OUTCTL_OVERRIDE_MASK|
						DEBUG_OUTCTL_NOT_LOGGED,
						"bc *",// Command to be executed
						DEBUG_EXECUTE_DEFAULT);
	}

	RetrieveBasicBlockInfoHashMap(Address,BasicBlockInfoHashMap,TRUE);
	IDebugBreakpoint *Bp;

#ifdef USE_ONE_SHOT_BREAKPOINT
	if(g_ExtControl->AddBreakpoint(DEBUG_BREAKPOINT_CODE,DEBUG_ANY_ID,&Bp)==S_OK)
	{
		if(Bp)
		{
			dprintf("%s: Addig BP %X(%X)\n",__FUNCTION__,Address);
			Bp->SetOffset(Address);
			if(Bp->AddFlags(DEBUG_BREAKPOINT_ENABLED)!=S_OK)
				dprintf("%s: Addig BP %X failed\n",__FUNCTION__,Address);

			//Update BreakPointInformationMap
			BP_INFO BpInfo;
			BpInfo.IsPermanent=TRUE;
			BpInfo.ReferenceCount=1;
			//BpInfo.LinkedBPs;
			BreakPointInformationMap.insert(pair<ULONG64,BP_INFO>(Address,BpInfo));
		}
	}
#else
	hash_map <ULONG64,PBASIC_BLOCK_INFO>::iterator BasicBlockInfoHashMapIterator;
	for(BasicBlockInfoHashMapIterator=BasicBlockInfoHashMap.begin();
		BasicBlockInfoHashMapIterator!=BasicBlockInfoHashMap.end();
		BasicBlockInfoHashMapIterator++)
	{
		ULONG64 BBAddress=BasicBlockInfoHashMapIterator->first;
		if(g_ExtControl->AddBreakpoint(DEBUG_BREAKPOINT_CODE,DEBUG_ANY_ID,&Bp)==S_OK)
		{
			if(Bp)
			{
				dprintf("%s: Addig BP %X\n",__FUNCTION__,BBAddress);
				Bp->SetOffset(BBAddress);
				if(Bp->AddFlags(DEBUG_BREAKPOINT_ENABLED)!=S_OK)
					dprintf("%s: Addig BP %X failed\n",__FUNCTION__,BBAddress);
			}
		}
	}
#endif

	if(!EventCallbackRegistered)
	{
		IDebugClient *NewClient;
		if(g_ExtClient->CreateClient(&NewClient)==S_OK && NewClient)
		{
			g_EventCb.SetMaximumNumberOfBasicBlocksToTrace(MaximumNumberOfBasicBlocksToTrace);
			g_EventCb.SetAutomaticContinueFlag(AutomaticContinue);
			if(OutputFilename)
				g_EventCb.SetOutputFilename(OutputFilename);
			if(NewClient->SetEventCallbacks(&g_EventCb)== S_OK)
			{
				EventCallbackRegistered=TRUE;
			}
		}
	}
	/*g_ExtControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS |
					DEBUG_OUTCTL_OVERRIDE_MASK |
					DEBUG_OUTCTL_NOT_LOGGED,
					"g",// Command to be executed
					DEBUG_EXECUTE_DEFAULT);*/
	FreeArgumentList((const char **)argv,argc);
	EXIT_API();
	return S_OK;
}

HRESULT CALLBACK debuglevel(PDEBUG_CLIENT4 Client,PCSTR args)
{
	DebugLevel=atoi(args);
	return S_OK;
}

/*
  A built-in help for the extension dll
*/
HRESULT CALLBACK help(PDEBUG_CLIENT4 Client,PCSTR args)
{
	INIT_API();

	UNREFERENCED_PARAMETER(args);
	dprintf("Help for viscope.dll\n"
			"  help				= Shows this help\n"
			"  dt <data type> - Saves data type relationship as DOT file\n"
			"  kb- Show callstack for current thread using callstack heuristics\n"
			"  u -o <filename> -l <level> <addr> - Show disassembly of the address\n"
			"    filename: Output filename\n"
			"    level: Maximum level for analysis\n"
			"  trace <addr> - Show disassembly of the address\n"
			"  outfile <addr> - Set output file\n"
			);
	EXIT_API();

	return S_OK;
}

