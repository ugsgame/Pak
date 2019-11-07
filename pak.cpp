#include <stdio.h>
#include <string.h>
#include <zlib.h>
#include <malloc.h>

//-----------------------------------------------------------------------------
// Definitions
//-----------------------------------------------------------------------------
typedef unsigned char TUint8;
typedef unsigned short TUint16;
typedef unsigned int TUint32;

TUint32 cryptTable[0x500];
#define FILE_NAME_LEN	80

typedef struct TPakHeader
{
	TUint16 fileNumber;	// how many files packed in the .pak
	TUint16 fileNameLen;	// eg. 256
	int fileNamePos;	// fileNamePos | 0x80000000(fileName compressed or not)
	int fnSize;	// zFNSize or oFNSize, oFNSize = fileNameLen*fileNumber
} TPakHeader;

typedef struct TPakIndex
{
	TUint32 nHash1;
	TUint32 nHash2;
	TUint32 filePos;
	TUint32 oSize;
	TUint32 zSize;
	TUint32 flag;	// reserved
} TPakIndex;

typedef struct TFileBlock
{
	TPakIndex index;
	char fileName[FILE_NAME_LEN];
	TUint8* oData;
	TUint8* zData;
} TFileBlock;

//-----------------------------------------------------------------------------
// Hash string
//-----------------------------------------------------------------------------
void InitCryptTable()
{
	TUint32 seed = 0x00100001, index1 = 0, index2 = 0, i;
	
	for(index1 = 0; index1 < 0x100; index1++)
	{
		for(index2 = index1, i = 0; i < 5; i++, index2 += 0x100)
		{
			TUint32 temp1, temp2;
			
			seed = (seed * 125 + 3) % 0x2AAAAB;
			temp1 = (seed & 0xFFFF) << 0x10;
			
			seed = (seed * 125 + 3) % 0x2AAAAB;
			temp2 = (seed & 0xFFFF);

			cryptTable[index2] = (temp1 | temp2);
		}
	}
}

int CharUpper(char lc)
{
	if (lc>='a' && lc<='z') return lc+'A'-'a';
	return lc;
}

TUint32 HashStr(const char* str, TUint32 hashType)
{
	TUint32 seed1 = 0x7FED7FED, seed2 = 0xEEEEEEEE;
	while (*str)
	{
		int uc = CharUpper(*str++);
		int index = (hashType << 8) + uc;
		seed1 = cryptTable[index] ^ (seed1 + seed2);
		seed2 = uc + seed1 + seed2 + (seed2 << 5) + 3;
	}
	return seed1;
}

void PrintAligned(TFileBlock* files, int fileNumber)
{
	int* len = (int*)malloc(sizeof(int)*fileNumber);
	int i, max = 0;
	
	for (i=0; i<fileNumber; i++)
	{
		len[i] = strlen(files[i].fileName);
		max = len[i]>max ? len[i]:max;
	}
	for (i=0; i<fileNumber; i++)
	{
		int dot;
		double ratio = files[i].index.zSize*100.0/files[i].index.oSize;

		printf("Pak: `%s' ", files[i].fileName);
		for (dot=0; dot<3+max-len[i]; dot++)
			printf(".");
		printf(" %6d -> %6d [%s%.1f%%]\n", files[i].index.oSize, files[i].index.zSize,
			ratio<10?" ":"", ratio);
	}
	free(len);
}

//-----------------------------------------------------------------------------
// Parse file
//-----------------------------------------------------------------------------
void ParseFile(const char* _fn, TFileBlock* fb)
{
	FILE* fp = NULL;
	char fn[256] = {0};
	int ret;
	int zLevel = 6;
	
	int len = strlen(_fn);
	if (_fn[len-2] == '/')
	{
		zLevel = _fn[len-1] - '0';
		memcpy(fn, _fn, len-2);
	}
	else
		strcpy(fn, _fn);
	
	if ((fp = fopen(fn, "rb")) == NULL)
	{
		printf("File not found! %s\n", fn);
		return;
	}
	fseek(fp, 0, SEEK_END);
	fb->index.oSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fb->oData = (TUint8*)malloc(fb->index.oSize);
	if ((unsigned int)(ret=fread(fb->oData, 1, fb->index.oSize, fp)) != fb->index.oSize)
	{
		printf("Read file error! %d != %d\n", ret, fb->index.oSize);
		free(fb->oData);
		fb->oData = NULL;
	}
	fclose(fp);

	fb->index.zSize = compressBound(fb->index.oSize);
	fb->zData = (TUint8*)malloc(fb->index.zSize);
	ret = compress2(fb->zData, &fb->index.zSize, fb->oData, fb->index.oSize, zLevel);
	if (ret != Z_OK)
	{
		printf("Compress error! %d\n", ret);
	}
	
	strcpy(fb->fileName, fn);
	fb->index.nHash1 = HashStr(fn, 1);
	fb->index.nHash2 = HashStr(fn, 2);
	
	return;
}

void CleanFileBlock(TFileBlock* fb)
{
	if (fb)
	{
		if (fb->oData) free(fb->oData);
		if (fb->zData) free(fb->zData);
	}
}

//-----------------------------------------------------------------------------
// main
//-----------------------------------------------------------------------------
#define Z_FNDATA	1

int main(int argc, char** argv)
{
	int i, oTotal = 0, zTotal = 0, wrote = 0;
	TPakHeader header;
	TFileBlock* files;
	FILE* fp;
	char *oFNData, *zFNData, *pakFile = argv[1];
	int oFNSize, zFNSize;

	memset(&header, 0, sizeof(header));
	header.fileNumber = argc-2;
	header.fileNameLen = FILE_NAME_LEN;

	files = (TFileBlock*)malloc(sizeof(TFileBlock)*header.fileNumber);

	InitCryptTable();

	for (i=0; i<header.fileNumber; i++)
	{
		memset(&files[i], 0, sizeof(TFileBlock));
		ParseFile(argv[i+2], &files[i]);
		if (i==0)
			files[i].index.filePos = sizeof(TPakHeader)+sizeof(TPakIndex)*header.fileNumber;
		else
			files[i].index.filePos = files[i-1].index.filePos + files[i-1].index.zSize;
		header.fileNamePos = files[i].index.filePos + files[i].index.zSize;
		oTotal += files[i].index.oSize;
	}
	
	PrintAligned(files, header.fileNumber);
	
	// compress fileNames
	oFNSize = FILE_NAME_LEN*header.fileNumber;
	oFNData = (char*)malloc(oFNSize);
	for (i=0; i<header.fileNumber; i++)
		memcpy(oFNData+FILE_NAME_LEN*i, files[i].fileName, FILE_NAME_LEN);
	
	if (Z_FNDATA)
	{
		header.fnSize = compressBound(oFNSize);
		zFNData = (char*)malloc(header.fnSize);
		compress2(zFNData, &header.fnSize, oFNData, oFNSize, 6);
		free(oFNData);
		header.fileNamePos |= 0x80000000;
	}
	else
	{
		header.fnSize = oFNSize;
		zFNData = oFNData;
	}

	// output .pak file
	fp = fopen(pakFile, "wb");
	if (fp == NULL)
	{
		printf("Write file failed!\n");
		goto _EXIT;
	}

	wrote += fwrite(&header, 1, sizeof(header), fp);
	zTotal += sizeof(header);

	for (i=0; i<header.fileNumber; i++)
		wrote += fwrite(&files[i].index, 1, sizeof(TPakIndex), fp);
	zTotal += sizeof(TPakIndex)*header.fileNumber;

	for (i=0; i<header.fileNumber; i++)
	{
		wrote += fwrite(files[i].zData, 1, files[i].index.zSize, fp);
		zTotal += files[i].index.zSize;
	}
	
	for (i=0; i<header.fileNumber; i++)
	{
		int j;
		for (j=i+1; j<header.fileNumber; j++)
		{
			if (files[i].index.nHash1 == files[j].index.nHash1)
				printf("%d=%d/nHash1: 0x%x\n", i,j,files[j].index.nHash1);
			if (files[i].index.nHash2 == files[j].index.nHash2)
				printf("%d=%d/nHash2: 0x%x\n", i,j,files[j].index.nHash2);
		}
	}

	wrote += fwrite(zFNData, 1, header.fnSize, fp);
	zTotal += header.fnSize;

	if (Z_FNDATA)
		free(zFNData);

	fclose(fp);
	
	//-
	if (zTotal != wrote)
		printf("\n>>> Pak error! %d wrote: %d\n", zTotal, wrote);
	else
		printf("\n>>> Paked: `%s' %d -> %d [%.1f%%].\n", pakFile, oTotal, zTotal, zTotal*100.0/oTotal);

_EXIT:
	for (i=0; i<header.fileNumber; i++)
		CleanFileBlock(&files[i]);
	free(files);

	return 0;
}

// end of file
