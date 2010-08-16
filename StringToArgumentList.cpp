#pragma warning(disable:4005)
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int StringToArgumentListDebugLevel=0;

enum {INSIDE_WHITESPACE,INSIDE_STR,INSIDE_QUOTE_STR};
char **StringToArgumentList(const char *Argument,int *pArgc)
{
	int Argc=0;
	char **Argv=NULL;

	int State=INSIDE_WHITESPACE;
	int StringStartPosition=0;

	for(DWORD i=0;i<strlen(Argument);i++)
	{
		int OldState=State;
		if(isspace(Argument[i]))
		{
			if(State!=INSIDE_QUOTE_STR)
			{
				State=INSIDE_WHITESPACE;
			}
		}else if(Argument[i]=='\"')
		{
			if(State==INSIDE_QUOTE_STR)
			{
				//End of String
				State=INSIDE_WHITESPACE;
			}else if(State==INSIDE_WHITESPACE)
			{
				StringStartPosition=i+1;
				State=INSIDE_QUOTE_STR;
			}else
			{
				//Error
			}
		}else if(State==INSIDE_WHITESPACE)
		{
			StringStartPosition=i;
			State=INSIDE_STR;
		}else if(State==INSIDE_STR || State==INSIDE_QUOTE_STR)
		{
		}else
		{
			//Error
		}
		if(((OldState==INSIDE_STR || OldState==INSIDE_QUOTE_STR) && !(State==INSIDE_STR || State==INSIDE_QUOTE_STR)) ||
			i==strlen(Argument)-1)
		{
			//End of string(StringStartPosition~i)
			//Start: Argument+StringStartPosition
			//Len: i-StringStartPosition
			int NewStrLen=i-StringStartPosition;
			if(i==strlen(Argument)-1)
				NewStrLen++;
			char *NewStr=(char *)malloc(NewStrLen+1);
			if(NewStr)
			{
				NewStr[NewStrLen]=NULL;
				memcpy(NewStr,Argument+StringStartPosition,NewStrLen);
				if(StringToArgumentListDebugLevel>2)
					printf("NewStr=%s\r\n",NewStr);
				Argc++;
				Argv=(char **)realloc(Argv,sizeof(char *)*Argc);
				if(Argv)
				{
					Argv[Argc-1]=NewStr;
					if(StringToArgumentListDebugLevel>2)
						printf("Argv[%d]=%s(%x)\r\n",Argc-1,Argv[Argc-1],Argv[Argc-1]);
				}else
				{
					free(NewStr);
				}
			}
		}
	}

	if(StringToArgumentListDebugLevel>2)
		printf("Argc=%d\r\n",Argc);
	if(pArgc)
		*pArgc=Argc;
	return Argv;
}

void FreeArgumentList(const char **Argv,int Argc)
{
	if(Argv)
	{
		for(int i=0;i<Argc;i++)
		{
			if(Argv[i])
				free((void *)Argv[i]);
		}
		free(Argv);
	}
}
