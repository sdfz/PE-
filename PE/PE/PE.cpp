#define _CRT_SECURE_NO_WARNINGS
#include<cstdio>
#include<cstdlib>
#include <memory.h>
#include <windows.h>
#include<iostream>
using namespace std;

//DOSͷ
PIMAGE_DOS_HEADER pDosHeader = NULL;
//NTͷ
PIMAGE_NT_HEADERS pNTHeader = NULL;
//��׼PEͷ
PIMAGE_FILE_HEADER pPEHeader = NULL;
//��ѡPEͷ
PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
//�ڱ�
PIMAGE_SECTION_HEADER pSectionHeader = NULL;
//�ڵ�����
int pSectionH[5];

char* read()
{
	FILE* fp = fopen("C:\\Users\\geer\\Desktop\\color.exe", "rb");
	if (fp == NULL)
	{
		printf("File open failed.\n");
		exit(1);
	}

	fseek(fp, 0, SEEK_END);
	int flen = ftell(fp);
	//rewind(fp);  rewind(fp);== fseek(fp, 0L, SEEK_SET);
	fseek(fp, 0L, SEEK_SET);
	//rewind(fp);

	char* buffer = (char*)malloc(sizeof(char) * flen + 1);
	memset(buffer, 0, flen + 1);
	//printf("%x\n", buffer);
	if (NULL == buffer)
	{
		printf("Memory malloc failed.\n");
		exit(1);
	}

	//���ݴ���
	fread(buffer, sizeof(char), flen, fp);
	//fwrite(buffer,sizeof(char),flen,fp);
	fclose(fp);
	return buffer;
}





char* PrintNTHeaders(char* rfile)
{
	char* pFileBuffer = NULL;


	pFileBuffer = rfile;
	if (!pFileBuffer)
	{
		printf("�ļ���ȡʧ��\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		free(pFileBuffer);
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//��ӡDOCͷ	
	printf("********************	DOCͷ	********************\n");
	printf("MZ��־��%x\n", pDosHeader->e_magic);
	printf("PEƫ�ƣ�%x\n", pDosHeader->e_lfanew);
	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		free(pFileBuffer);
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)(((int)pFileBuffer) + pDosHeader->e_lfanew);
	//��ӡNTͷ	
	printf("********************	NTͷ	********************\n");
	printf("NT: %x\n", pNTHeader->Signature);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);

	printf("********************	��׼PEͷ	********************\n");
	printf("PE: %x\n", pPEHeader->Machine);
	printf("�ڵ�����: %x\n", pPEHeader->NumberOfSections);
	printf("SizeOfOptionalHeader: %x\n", pPEHeader->SizeOfOptionalHeader);
	printf("Characteristics: %x\n", pPEHeader->Characteristics);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	printf("********************	OPTIOIN_PEͷ	********************\n");
	printf("OPTION_PE:%x\n", pOptionHeader->Magic);
	printf("SizeOfCode:%x\n", pOptionHeader->SizeOfCode);
	printf("SizeOfInitializedData:%x\n", pOptionHeader->SizeOfInitializedData);
	printf("SizeOfUninitializedData:%x\n", pOptionHeader->SizeOfUninitializedData);
	printf("AddressOfEntryPoint:%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("BaseOfCode:%x\n", pOptionHeader->BaseOfCode);
	printf("BaseOfData:%x\n", pOptionHeader->BaseOfData);
	printf("ImageBase:%x\n", pOptionHeader->ImageBase);
	printf("SectionAlignment:%x\n", pOptionHeader->SectionAlignment);
	printf("FileAlignment:%x\n", pOptionHeader->FileAlignment);
	printf("SizeOfImage:%x\n", pOptionHeader->SizeOfImage);
	printf("SizeOfHeaders:%x\n", pOptionHeader->SizeOfHeaders);
	printf("CheckSum:%x\n", pOptionHeader->CheckSum);
	printf("SizeOfStackReserve:%x\n", pOptionHeader->SizeOfStackReserve);
	printf("SizeOfStackCommit:%x\n", pOptionHeader->SizeOfStackCommit);
	printf("SizeOfHeapReserve:%x\n", pOptionHeader->SizeOfHeapReserve);
	printf("SizeOfHeapCommit:%x\n", pOptionHeader->SizeOfHeapCommit);
	printf("LoaderFlags:%x\n", pOptionHeader->LoaderFlags);

	//PE �ڱ�
	printf("********************	PE�ڱ�	********************\n");
	char sectionName[9] = { 0 };

	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + sizeof(IMAGE_OPTIONAL_HEADER32));

	
	for (int k = 0; k < pPEHeader->NumberOfSections; k++, pSectionHeader++)
	{
		memcpy(sectionName, pSectionHeader->Name, 8);
		printf("Name:%s\n", sectionName);
		printf("Misc.VirtualSize:%x\n", pSectionHeader->Misc.VirtualSize);
		printf("VirtualAddress:%x\n", pSectionHeader->VirtualAddress);
		printf("SizeOfRawData:%x\n", pSectionHeader->SizeOfRawData);
		printf("PointerToRawData:%x\n", pSectionHeader->PointerToRawData);
		printf("PointerToRelocations:%x\n", pSectionHeader->PointerToRelocations);
		printf("PointerToLinenumbers:%x\n", pSectionHeader->PointerToLinenumbers);
		printf("NumberOfRelocations:%x\n", pSectionHeader->NumberOfRelocations);
		printf("NumberOfLinenumbers:%x\n", pSectionHeader->NumberOfLinenumbers);
		printf("Characteristics:%x\n", pSectionHeader->Characteristics);

		pSectionH[k] = (int)pSectionHeader;
		printf("\n");
	}

	//���ÿ���ڵ�data
	//unsigned int Pointdata = 0;
	//char PointRawData[5632] = { 0 };

	//PIMAGE_SECTION_HEADER p123 = (PIMAGE_SECTION_HEADER)pSectionH[0];
	//Pointdata = p123->SizeOfRawData;//16����ת����10����
	//memcpy(PointRawData, (char*)((int)pFileBuffer + p123->PointerToRawData), Pointdata);

	//for (unsigned int i = 0; i < Pointdata; i++)
	//{
	//	printf("%-02x  ", (unsigned char)PointRawData[i]);
	//	if ((i + 1) % 16 == 0)
	//	{
	//		printf("\n");
	//	}
	//}



	//�ͷ��ڴ�	
	//free(pFileBuffer);

	return pFileBuffer;

}


char* ImageBuffer(char** rFile)
{

	////DOSͷ
	//PIMAGE_DOS_HEADER pDosHeader = NULL;
	////NTͷ
	//PIMAGE_NT_HEADERS pNTHeader = NULL;
	////��׼PEͷ
	//PIMAGE_FILE_HEADER pPEHeader = NULL;
	////��ѡPEͷ
	//PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	////�ڱ�
	//PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//int pSectionH[6];

	int imgdadaxiao = pOptionHeader->SizeOfImage;//����img��С
	int headxdaxiao = pOptionHeader->SizeOfHeaders;//ͷ�����Ĵ�С

	char* imgbuffer = (char*)malloc(sizeof(char) * imgdadaxiao + 1);
	memset(imgbuffer, 0, imgdadaxiao + 1);
	
	memcpy(imgbuffer, *rFile, headxdaxiao);

	for (int i = 0; i < 5;i++)
	{
		//�ļ��е�һ���ڱ�λ��ƫ�Ƶ�ַ
		PIMAGE_SECTION_HEADER jie1 = (PIMAGE_SECTION_HEADER)pSectionH[i];		
		int imgadd = jie1->VirtualAddress;//�ڴ��е�һ����λ��ƫ�Ƶ�ַ
		int filewx = jie1->PointerToRawData; //�ļ�λ�ÿ�ʼ����
		unsigned int jiedaxiao = jie1->SizeOfRawData;//�ļ�λ�õĴ�С

		memcpy( imgbuffer + imgadd, (char*)((int)* rFile + filewx), jiedaxiao);
		
		//�ж�Misc.VirtualSize > SizeOfRawData��> ��������֮��Ĳ�ֵ׷�ӵ�headxdaxiao����
		if (jie1->Misc.VirtualSize > jie1->SizeOfRawData)
		{
			int jie = jie1->Misc.VirtualSize - jie1->SizeOfRawData;
			memcpy(imgbuffer + imgadd + jiedaxiao, (char*)((int)* rFile + filewx), jie);
			memset(imgbuffer + imgadd + jiedaxiao, 0, jie);
		}
	}
	return imgbuffer;
}

int daxiao123;
char* NewBuffer(char* imgFile,char* rFile)
{
	//���������ļ���С�������һ����+����
	PIMAGE_SECTION_HEADER NewpSectionHeader = NULL;
	NewpSectionHeader = (PIMAGE_SECTION_HEADER)pSectionH[4];
	int daxiao123 = ((int)NewpSectionHeader->PointerToRawData + (int)NewpSectionHeader->SizeOfRawData);

	char* Newf = (char*)malloc(sizeof(char) * daxiao123 + 1);
	memset(Newf, 0, daxiao123 + 1);

	//��ȡfile and img�ļ�ͷ�Ĵ�С��Head���ֶ�һ��
	int headxdaxiao = pOptionHeader->SizeOfHeaders;//ͷ�����Ĵ�С
	memcpy(Newf, rFile, headxdaxiao);


	for (int i = 0; i < 5; i++)
	{
		//�ļ��е�һ���ڱ�λ��ƫ�Ƶ�ַ
		PIMAGE_SECTION_HEADER jie1 = (PIMAGE_SECTION_HEADER)pSectionH[i];
		int imgadd = jie1->VirtualAddress;//�ڴ��е�һ����λ��ƫ�Ƶ�ַ
		int filewx = jie1->PointerToRawData; //�ļ�λ�ÿ�ʼ����
		unsigned int jiedaxiao = jie1->SizeOfRawData;//�ļ�λ�õĴ�С

		memcpy((char*)Newf + filewx, (char*)((int)imgFile + imgadd), jiedaxiao);

	}



	return Newf;
}


void cunpan(char* file)
{

		FILE* fp = fopen("C:\\Users\\geer\\Desktop\\color2.exe", "wb");
		if (fp == NULL)
		{
			printf("File open failed.\n");
			exit(1);
		}
		fseek(fp, 0L, SEEK_SET);
		fwrite(file,sizeof(char), 61440, fp);
		fclose(fp);
		//return buffer;
	

}


int main()
{
	char* rfile = read();
	char* readFile = PrintNTHeaders(rfile);
	char* imgFile = ImageBuffer(&readFile);
	char* NewBFile = NewBuffer(imgFile,readFile);
	cunpan(NewBFile);
	

	free(readFile);
	free(imgFile);
	free(NewBFile);
	system("pause");
	return 0;
}