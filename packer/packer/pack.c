#include "pack.h"



// Stub insertion by post build event on stub project
// Ignore errors here until build

uint8_t stub[] = { 
#include "stub.h" 
};
int sizeOfStub = sizeof(stub);

int pack(uint8_t * input, uint8_t ** output, uint8_t * key, uint32_t * rsize, uint32_t insize) 
{
	

	printf("[+] Packing\n");

	// Load/Validate the PE data from the bytes

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)input;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] Does not match PE DOS header");
		return FALSE;
	}
	printf("[+] Header correct\n");

	//Compress The input data
	printf("[+] Attempting to compress\n");
	inCompress(input, insize, output, rsize);
	printf("[+] Compression complete\n");

	// Encrypt the compressed data
	printf("[+] Encrypting\n");
	inEncrypt(output, rsize, key);
	printf("[+] Encryption complete\n");

	// Load the PE for the stub
	// Extract / Manipulate stub PE data as needed

	//stub dos header
	PIMAGE_DOS_HEADER stubDosHeader = (PIMAGE_DOS_HEADER)stub;

	// Combine stub and section by calling ----> add section?
	// give the packed data as arguments
	printf("[+] Adding section\n");
	uint32_t realSize = *rsize;

	stubAddSection(rsize, stub, sizeOfStub, stubDosHeader, key);
	printf("[+] Section added\n");

	
	

	//makes final buffer size the size of the stub + the size of exe file
	//calculate final size, init buffer to final size
	uint32_t finSize = sizeOfStub + *rsize;
	uint8_t * fin = (uint8_t *)calloc(1, finSize);

	//copy the stub then compressed+encrypt file to buffer
	memcpy(fin, stub, sizeOfStub);
	memcpy(fin + sizeOfStub, *output, realSize);

	//set buffer and rsize to the final buffer and finsize respectively
	free(*output);
	*output = fin;
	*rsize = finSize;	


	printf("[+] Patching key\n");

	patchKey(*output, *rsize, key);

	printf("[+] Key Pathced\n");

	return TRUE;
}

int patchKey(uint8_t * data, uint32_t size, uint8_t * key) {

	//Finally, add the key in
	int kOffset = 0;

	for (uint32_t i = 0; i < size; i++)
	{
		if (*((uint32_t *)(&data[i])) == MAGIC_KEY) {
			kOffset = i;
			i = size; // jump out loop.
		}
	}
	for (size_t i = 0; i < KEY_LEN; i++)
	{
		data[kOffset + i] = key[i];
	}

	return TRUE;
}


	// Fix up the stub PE header to include the extra section
int stubAddSection( uint32_t * rsize, uint8_t * stub, int sizeOfStub, PIMAGE_DOS_HEADER stubDosHeader, uint8_t * key) {

	//getting file header to calculate the amount of sections
	PIMAGE_FILE_HEADER stubFileHeader = (PIMAGE_FILE_HEADER)(stub + stubDosHeader->e_lfanew + sizeof(DWORD));

	//get optional header to add section (don't need at this moment)
	PIMAGE_OPTIONAL_HEADER stubOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(stub + stubDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	
	//get section header (not sure if its the start of first or end of last ---> seems like end of last)
	PIMAGE_SECTION_HEADER stubSectionHeader = (PIMAGE_SECTION_HEADER)(stub + stubDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));


	//check that we have enough size for another section
	uint32_t sectionTableStart = stubSectionHeader - stub;
	uint32_t minPtrToRawData = stubSectionHeader[0].PointerToRawData;
	for (int i = 1; i < stubFileHeader->NumberOfSections; i++)
	{
		if (minPtrToRawData > stubSectionHeader[i].PointerToRawData)
		{
			minPtrToRawData = stubSectionHeader[i].PointerToRawData;
		}
	}
	uint32_t realSizeOfSectionTable = minPtrToRawData - sectionTableStart;
	if ((stubFileHeader->NumberOfSections * 40) + 40 > realSizeOfSectionTable)
	{
		printf("\t[-] Not enough space in sections table");
		exit(1);
	}

	// (0) set the name of the section (.ryanb)
	ZeroMemory(&stubSectionHeader[stubFileHeader->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&stubSectionHeader[stubFileHeader->NumberOfSections].Name, ".ryanb", 8);

	// increment the number of sections(stupid place for this but oh well) 
	stubFileHeader->NumberOfSections++;

	// (1) set virtual size to the size of the ouptut
	uint32_t virtSize = *rsize;
	while ((virtSize % stubOptionalHeader->SectionAlignment) != 0)
	{
		virtSize = virtSize + 1;
	}
	stubSectionHeader[stubFileHeader->NumberOfSections - 1].Misc.VirtualSize = virtSize;
	
	// (2) set virtual address
	uint32_t virtAddress = stubSectionHeader[stubFileHeader->NumberOfSections - 2].VirtualAddress + stubSectionHeader[stubFileHeader->NumberOfSections - 2].Misc.VirtualSize;
	while ((virtAddress % stubOptionalHeader->SectionAlignment) != 0)
	{
		virtAddress++;
	}
	stubSectionHeader[stubFileHeader->NumberOfSections -1].VirtualAddress = virtAddress;
	
	// (3) set size of raw data
	uint32_t maintainRsize = *rsize;
	uint32_t rawSize = *rsize;
	while ((rawSize % stubOptionalHeader->FileAlignment) != 0)
	{
		rawSize = rawSize + 1;
	}
	stubSectionHeader[stubFileHeader->NumberOfSections - 1].SizeOfRawData= rawSize;
	*rsize = rawSize;


	// (4) set pointer to raw data
	uint32_t ptrToRaw = stubSectionHeader[stubFileHeader->NumberOfSections - 2].PointerToRawData + stubSectionHeader[stubFileHeader->NumberOfSections - 2].SizeOfRawData;
	stubSectionHeader[stubFileHeader->NumberOfSections-1].PointerToRawData = ptrToRaw;

	// (5) setting the charachteristic for .ryanb (rwx)
	stubSectionHeader[stubFileHeader->NumberOfSections - 1].Characteristics = 0xE00000E0;

	// (6) setting the new size of image
	stubOptionalHeader->SizeOfImage = rawSize + stubOptionalHeader->SizeOfImage;

	// (7) replacing pointer to buffer with the VA of .ryanb section
	// search for flag value
	uint32_t findMe = 0;
	for(int i = 0; i <= stubFileHeader->NumberOfSections; i++)
	{
		if (strcmp(stubSectionHeader[stubFileHeader->NumberOfSections - i].Name	,".data") == 0)
		{

			for (int x = 0; x < stubSectionHeader[stubFileHeader->NumberOfSections - i].SizeOfRawData; x++)
			{
				if ((*(uint32_t *)(stub + stubSectionHeader[stubFileHeader->NumberOfSections - i].PointerToRawData + x)) == MAGIC_ADDR) //flag = 0x31323334
				{
					findMe = x + stubSectionHeader[stubFileHeader->NumberOfSections - i].VirtualAddress + stubOptionalHeader->ImageBase;

				}
			}
		}
	}

	// seach for pointer to VA address, then patch
	for (int i = 0; i <= stubFileHeader->NumberOfSections; i++)
	{
		if (strcmp(stubSectionHeader[stubFileHeader->NumberOfSections - i].Name, ".text") == 0)
		{
			for (int x = 0; x < stubSectionHeader[stubFileHeader->NumberOfSections - i].SizeOfRawData; x++)
			{
				if ((*(uint32_t *)(stub + stubSectionHeader[stubFileHeader->NumberOfSections - i].PointerToRawData + x)) == findMe)
				{
					printf("\t\t[.ryanb section virtual address] %x \n", (stubSectionHeader[stubFileHeader->NumberOfSections - 1].VirtualAddress) + stubOptionalHeader->ImageBase);
					(*(uint32_t *)(stub + stubSectionHeader[stubFileHeader->NumberOfSections - i].PointerToRawData + x)) = (stubSectionHeader[stubFileHeader->NumberOfSections - 1].VirtualAddress) + stubOptionalHeader->ImageBase;
				}
			}
		}
	}

	// (8) passing the size value over 
	for (int i = 0; i <= stubFileHeader->NumberOfSections; i++)
	{
		if (strcmp(stubSectionHeader[stubFileHeader->NumberOfSections - i].Name, ".data") == 0)
		{
			for (int x = 0; x < stubSectionHeader[stubFileHeader->NumberOfSections - i].SizeOfRawData; x++)
			{
				if ((*(uint32_t *)(stub + stubSectionHeader[stubFileHeader->NumberOfSections - i].PointerToRawData + x)) == MAGIC_SIZE) 
				{
					(*(uint32_t *)(stub + stubSectionHeader[stubFileHeader->NumberOfSections - i].PointerToRawData + x)) = maintainRsize;//size
				}
			}
		}
	}

	return TRUE;
}


int inCompress(uint8_t * input, int insize, uint8_t ** output,int * rsize) {
	COMPRESSOR_HANDLE Compressor = NULL;
	SIZE_T CompressedDataSize, CompressedBufferSize;

	
	// Create an Xpress compressor.
	if (!CreateCompressor(COMPRESS_ALGORITHM_XPRESS,NULL,&Compressor)) {	
		printf("\t[-] Failed to create a compressor Code:%d\n", GetLastError());
		return FALSE;
	}               
	
	// Query compressed buffer size.
	// Proto Compress(handle,input buffer,uncompressed size,compressed buffer,compressed buffer size, compressed data size)
	if (!Compress(Compressor, input, insize, NULL, 0, &CompressedBufferSize)){
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			printf("\t[-] Failed to get the size of the buffer needed to compress. Code:%d\n", GetLastError());
			return FALSE;
		}

	}
	
	// allocate new size for output.
	*output = realloc(*output,CompressedBufferSize);
	if (!*output) {
		printf("\t[-] Failed to reallocate output buffer for compression Code:%d\n", GetLastError());
		return FALSE;
	}
	*rsize = CompressedBufferSize;

	//  Call Compress() again to do real compression and output the compressed data
	if(!Compress(Compressor, input, insize, *output, CompressedBufferSize, &CompressedDataSize)){
		printf("\t[-] Failed to compress data Code:%d\n", GetLastError());
		return FALSE;
	}

	printf("\t[+] Input Size: %d\n", insize);
	printf("\t[+] Output Size:%d\n", CompressedDataSize);
	*output = realloc(*output, CompressedDataSize);
	*rsize = CompressedDataSize;
	CloseCompressor(Compressor);

	return TRUE;
}

int inEncrypt(uint8_t ** buffer, int * rsize,uint8_t * key) {
	
	// Initialization
	aes256_context ctx;
	aes256_init(&ctx, key);

	// Pad the output before encryption
	uint8_t padCount = 16 - (*rsize % 16); 
	printf("\t[+] Padding with %d bytes\n", padCount);


	*buffer = realloc(*buffer, *rsize + padCount);

	// Zero out new space
	for (int i = *rsize; i < padCount+*rsize; i++)
	{
		(*buffer)[i] = 0;
	}

	// set size to new value
	*rsize = *rsize + padCount;
	printf("\t[+] Buffer size is now %d bytes\n", *rsize);

	// Store the pad count as the last byte
	(*buffer)[(*rsize)-1] = padCount;

	// Need to break into 16 byte chunks
	for (int i = 0; i < *rsize / 16; i++)
	{
		aes256_encrypt_ecb(&ctx, (*buffer)+(i*16));
	}

	aes256_done(&ctx);

	printf("\t[+] Encryption Finished\n");


	return TRUE;
}

// Test compression
// https://msdn.microsoft.com/en-us/library/windows/desktop/hh968104(v=vs.85).aspx
int testCompress(uint8_t * input,size_t insize)
{
	COMPRESSOR_HANDLE Compressor = NULL;
	COMPRESSOR_HANDLE Decompressor = NULL;
	PBYTE CompressedBuffer = NULL;
	PBYTE DecompressedBuffer = NULL;
	BOOL Success;
	SIZE_T CompressedDataSize, CompressedBufferSize,DecompressedBufferSize, DecompressedDataSize;
	ULONGLONG StartTime, EndTime;
	double TimeDuration;

	//  Create an Xpress compressor.
	Success = CreateCompressor(
		COMPRESS_ALGORITHM_XPRESS, //  Compression Algorithm
		NULL,                           //  Optional allocation routine
		&Compressor);                   //  Handle

	if (!Success)
	{
		printf("Fail!");
	}

	//  Query compressed buffer size.
	Success = Compress(
		Compressor,                  //  Compressor Handle
		input,						 //  Input buffer, Uncompressed data
		insize,               //  Uncompressed data size
		NULL,                        //  Compressed Buffer
		0,                           //  Compressed Buffer size
		&CompressedBufferSize);      //  Compressed Data size


	CompressedBuffer = (PBYTE)malloc(CompressedBufferSize);

	StartTime = GetTickCount64();

	//  Call Compress() again to do real compression and output the compressed
	//  data to CompressedBuffer.
	Success = Compress(
		Compressor,             //  Compressor Handle
		input,            //  Input buffer, Uncompressed data
		insize,          //  Uncompressed data size
		CompressedBuffer,       //  Compressed Buffer
		CompressedBufferSize,   //  Compressed Buffer size
		&CompressedDataSize);   //  Compressed Data size

	EndTime = GetTickCount64();

	//  Get compression time.
	TimeDuration = (EndTime - StartTime) / 1000.0;

	printf("\n\t[?] Compression Time: %.2f seconds\n", TimeDuration);
	printf("\t[?] Input Size: %d\n", insize);
	printf("\t[?] Compression Size:%d\n", CompressedDataSize);
	
	//  Create an Xpress decompressor.
	Success = CreateDecompressor(
		COMPRESS_ALGORITHM_XPRESS, //  Compression Algorithm
		NULL,                           //  Optional allocation routine
		&Decompressor);                   //  Handle

	Success = Decompress(
		Decompressor,                //  Compressor Handle
		CompressedBuffer,            //  Compressed data
		CompressedDataSize,               //  Compressed data size
		NULL,                        //  Buffer set to NULL
		0,                           //  Buffer size set to 0
		&DecompressedBufferSize);    //  Decompressed Data size

	DecompressedBuffer = (PBYTE)malloc(DecompressedBufferSize);

	Success = Decompress(
		Decompressor,               //  Decompressor handle
		CompressedBuffer,           //  Compressed data
		CompressedDataSize,              //  Compressed data size
		DecompressedBuffer,         //  Decompressed buffer
		DecompressedBufferSize,     //  Decompressed buffer size
		&DecompressedDataSize);     //  Decompressed data size

	if (!Success)
	{
		printf("Cannot decompress data: %d.\n", GetLastError());
	}

	printf("\t[?] Decompressed Size:%d\n", DecompressedDataSize);

	CloseDecompressor(Decompressor);
	CloseCompressor(Compressor);
	free(CompressedBuffer);
	free(DecompressedBuffer);

	return 0;
}



int testAes(uint8_t * key) {
	//Test aes 
	aes256_context ctx;
	char text[16] = "Hellotest16____";
	printf("\t[?] Encrypting %s\n", text);
	printf("\t[?] With Key:");
	for (size_t i = 0; i < 32; i++)
	{
		printf("%02x", key[i] & 0xff);
	}
	printf("\n\t[?] In hex: ");

	for (size_t i = 0; i < 16; i++)
	{
		printf("%02x ", text[i] & 0xff);
	}
	aes256_init(&ctx, key);
	aes256_encrypt_ecb(&ctx,text);
	printf("\n\t[?] Got:");
	for (size_t i = 0; i < 16; i++)
	{
		printf("%02x ", text[i] & 0xff);
	}
	aes256_decrypt_ecb(&ctx, text);
	printf("\n\t[?] Got back %s\n", text);
	aes256_done(&ctx);

	return 0;
}

