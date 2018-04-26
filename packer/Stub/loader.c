#include "loader.h"


int loader(uint8_t * data, uint8_t dataSize)
{
	// Get information from PE headers and Get sections from PE image
	PIMAGE_DOS_HEADER bufferDosHeader = (PIMAGE_DOS_HEADER)data;
	PIMAGE_FILE_HEADER bufferFileHeader = (PIMAGE_FILE_HEADER)(data + bufferDosHeader->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER bufferOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(data + bufferDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER bufferSectionHeader = (PIMAGE_SECTION_HEADER)(data + bufferDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	//verify sections are correct
	for (int i = bufferFileHeader->NumberOfSections; i > 1; i--)
	{
		printf("\t[Name of section] %s\n", bufferSectionHeader[bufferFileHeader->NumberOfSections - i].Name);
	}
	
	// Reserve memory for the program
	// Attempt to get prefered base address. If cannot calculate offset.
	//virtual protect will help change the memory permissions
	printf("[+] Reserving memory for pgrm\n");
	uint64_t offset = 0;
	uint8_t * baseAddress = VirtualAlloc(bufferOptionalHeader->ImageBase, bufferOptionalHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (baseAddress == NULL)
	{
		printf("\t[+] Preffered not received...\n");
		baseAddress = VirtualAlloc(NULL, bufferOptionalHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		offset = bufferOptionalHeader->ImageBase - (int64_t)baseAddress;
		printf("\t[base address] %x\n", bufferOptionalHeader->ImageBase);
		printf("\t[non-standard BA] %x\n", baseAddress);
		printf("\t[OFFSET] %x\n", offset);
		exit(0);
	}
	else
	{
		printf("\t[+] Preffered recieved\n");
	}

	// Load sections from the sections table into memory (only text and data)

	uint8_t * currAddr;
	for (int i = bufferFileHeader->NumberOfSections; i > 0; i--)
	{
		printf("hello\n");
		currAddr = bufferSectionHeader[bufferFileHeader->NumberOfSections - i].VirtualAddress + offset + bufferOptionalHeader->ImageBase;
		
		printf("%x\n", currAddr);
		CopyMemory(currAddr, data + bufferSectionHeader[bufferFileHeader->NumberOfSections - i].PointerToRawData, bufferSectionHeader[bufferFileHeader->NumberOfSections - i].SizeOfRawData);
	}


	// Perform relocations


	// Handle the imports in the imports table here


	// Jump to entry point of the program
	//Cast entry point address to function

	 
	// free any dynamically allocated memory

	return FALSE;
}
