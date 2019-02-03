#include "loader.h"


int loader(uint8_t * data)
{
	// Get information from PE headers and Get sections from PE image
	PIMAGE_DOS_HEADER bufferDosHeader = (PIMAGE_DOS_HEADER)data;

	PIMAGE_NT_HEADERS bufferNTHeader = (PIMAGE_NT_HEADERS)((BYTE *)bufferDosHeader + bufferDosHeader->e_lfanew);

	PIMAGE_FILE_HEADER bufferFileHeader = (PIMAGE_FILE_HEADER)(data + bufferDosHeader->e_lfanew + sizeof(DWORD));
	
	PIMAGE_OPTIONAL_HEADER bufferOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(data + bufferDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	
	PIMAGE_SECTION_HEADER bufferSectionHeader = (PIMAGE_SECTION_HEADER)(data + bufferDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	uint8_t relocFlag = 0;


	//verify sections are correct
	for (int i = bufferFileHeader->NumberOfSections; i > 0; i--)
	{
		//printf("\t[Name of section] %s\n", bufferSectionHeader[bufferFileHeader->NumberOfSections - i].Name);
	}
	
	// Reserve memory for the program
	// Attempt to get prefered base address. If cannot calculate offset.
	//virtual protect will help change the memory permissions
	printf("[+] Reserving memory for pgrm\n");
	int32_t offset = 0;
	uint8_t * baseAddress = VirtualAlloc((LPVOID)bufferOptionalHeader->ImageBase, bufferOptionalHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (baseAddress == NULL)
	{
		baseAddress = VirtualAlloc(NULL, bufferOptionalHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		offset = (uint32_t)baseAddress - bufferOptionalHeader->ImageBase;

		//printf("\t[OFFSET] %x\n", offset);
		//printf("\t[non-standard BA] %x\n", baseAddress);
		printf("\t[+] Preffered not received...\n");

		relocFlag = 1;
		//exit(0);
	}
	else
	{
		printf("\t[+] Preffered recieved\n");
		//printf("\t[standard BA recieved] %x\n", bufferOptionalHeader->ImageBase);
		//exit(0);
	}

	// Load sections from the sections table into memory (only text and data)

	uint8_t * currAddr = { 0 };

	//places each section in memory one by one
	for (int i = bufferFileHeader->NumberOfSections; i > 0; i--)
	{
		currAddr = (uint8_t *)(bufferSectionHeader[bufferFileHeader->NumberOfSections - i].VirtualAddress + offset + bufferOptionalHeader->ImageBase);
		//printf("\t[Loaded into mem address] %x\n", currAddr);
		CopyMemory(currAddr, data + bufferSectionHeader[bufferFileHeader->NumberOfSections - i].PointerToRawData, bufferSectionHeader[bufferFileHeader->NumberOfSections - i].SizeOfRawData);
	}


	// Perform relocations 
	
	if (relocFlag)
	{
		printf("[+] Perfroming relocations\n");

		// getting pointer to base of relocation
		PIMAGE_BASE_RELOCATION baseRelocation = (PIMAGE_BASE_RELOCATION)(baseAddress + bufferNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		//printf("[size of block] %x\n", baseRelocation->SizeOfBlock); 
		
		//printf("[theoretical entry address] %x\n", baseRelocation->VirtualAddress + bufferOptionalHeader->ImageBase);

		// while no more blocks
		while (baseRelocation->SizeOfBlock)
		{

			// address of the begining of the relocation (0x...1000 for calc_pi)
			uint32_t  currentAddress = baseAddress + baseRelocation->VirtualAddress; 

			// number of relocatioins to be performed in this section
			DWORD relocCount = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);  

			// +1 because base relocation is a pointer so we are passing va and size of blocks
			WORD * typeOffset = baseRelocation + 1;

			for (int i = 0; i < relocCount - 1; i++)
			{
				// gets the type,  in this case they should be all highlow
				uint8_t status = (typeOffset[i] >> 12) & 0xff;

				// get offset from the previous reloc to next reloc
				uint32_t thingOffset = (typeOffset[i]) & 0xfff;

				// verify type
				if (IMAGE_REL_BASED_HIGHLOW == status)
				{
					//fix up the address to point at the correct space
					//printf("[+] %x\n", thingOffset);
					uint32_t * fixUpLoc = currentAddress + thingOffset;
					*fixUpLoc = *fixUpLoc + offset;
				}
				else
				{
					printf("[-] cannot handle relocations");
					exit(0);
				}		
			}
			// increment to get the next block
			baseRelocation = (PIMAGE_BASE_RELOCATION)(((DWORD)baseRelocation) + baseRelocation->SizeOfBlock);
		}
	}
	


	// Handling imports table

	//get image descriptor
	PIMAGE_IMPORT_DESCRIPTOR  bufferImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + bufferNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//printf("[current image base] %x\n", baseAddress);

	if (!bufferImportDescriptor)
	{
		printf("%s", "[-] IAT missing\n");
		exit(0);
	}

	//load into memory
	while (bufferImportDescriptor->Name != 0)
	{
		//verify name

		uint8_t * currentDLLName = (uint8_t *)(baseAddress + bufferImportDescriptor->Name);
		//printf("[Current lib] %s\n", currentDLLName);
		//load dll into memory hMod = LoadLibraryA((CHAR*) pLibName);
		HMODULE hmod = LoadLibraryA((uint8_t *)currentDLLName);

		//verify hmod
		if (!hmod)
		{
			printf("%s", "[-] Failed to load Library into memory");
			exit(0);
		}

		//get current thunk
		PIMAGE_THUNK_DATA currentThunk = (PIMAGE_THUNK_DATA)(baseAddress + bufferImportDescriptor->FirstThunk);

		//while more to check
		while (currentThunk->u1.AddressOfData != 0)
		{			
			//get current function and load thenget proc address
			PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + currentThunk->u1.AddressOfData);
			currentThunk->u1.AddressOfData = (uint32_t)GetProcAddress(hmod, (uint8_t *)importByName->Name);
			//printf("%s\n", importByName->Name);

			//verify its load location
			if (!currentThunk->u1.AddressOfData)
			{
				printf("%s", "[-] Unable to handle imports\n");
				exit(0);
			}
			//next thunk
			currentThunk++;
		}
		//get next dll
		bufferImportDescriptor++;

	}
	

	// Jump to entry point of the program
	//Cast entry point address to function
	
	//getting entry point
	uint8_t * entryPoint = baseAddress + bufferNTHeader->OptionalHeader.AddressOfEntryPoint;

	//printf("Entry point: %x\n", entryPoint);
	printf("%s", "[+] Attempting to execute\n");	

	//casting to function and executing
	int(*exec)() = (int(*)())(entryPoint);
	exec();

	//attempting to execute

	printf("[+] execution complete\n");
	 
	// free any dynamically allocated memory

	return FALSE;
}
