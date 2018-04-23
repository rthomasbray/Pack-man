#include "pack.h"

// Stub insertion by post build event on stub project
// Ignore errors here until build


uint8_t stub[] = { 
#include "stub.h" 
};
int sizeOfStub = sizeof(stub);


int pack(uint8_t * input, uint8_t ** output, uint8_t * key, uint32_t * rsize, uint32_t insize) {

	printf("[+] Packing\n");

	// Load/Validate the PE data from the bytes
	// TODO (complete)
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)input;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] Does not match PE DOS header");
		return FALSE;
	}
	printf("[+] Header correct\n");


	//Compress The input data
	// TODO (complete)
	printf("[+] Attempting to compress\n");
	inCompress(input, insize, output, rsize);
	printf("[+] Compression complete\n");

	// Encrypt the compressed data
	// TODO (complete)
	printf("[+] Encrypting\n");
	inEncrypt(output, rsize, key);
	printf("[+] Encryption complete\n");

	// Load the PE for the stub
	// Extract / Manipulate stub PE data as needed
	// TODO (maybe complete)

	//stub dos header
	PIMAGE_DOS_HEADER stubDosHeader = (PIMAGE_DOS_HEADER)stub;

	// Combine stub and section by calling ----> add section?
	// give the packed data as arguments
	// TODO (maybe complete)
	printf("[+] Adding section\n");
	stubAddSection(rsize, stub, sizeOfStub, stubDosHeader);
	printf("[+] Section added\n");

	//makes final buffer size the size of the stub + the size of exe file
	//TODO (maybe complete)
	printf("[debug] final rsize = %x\n", *rsize); 
	printf("[debug] stubsize = %x\n", sizeOfStub);

	//calculate final size, init buffer to final size
	uint32_t finSize = sizeOfStub + *rsize;
	uint8_t * fin = (uint8_t *)malloc(finSize);

	//copy the stub then compressed+encrypt file to buffer
	memcpy(fin, stub, sizeOfStub);
	memcpy(fin + sizeOfStub, *output, *rsize);

	//set buffer and rsize to the final buffer and finsize respectively
	free(*output);
	*output = fin;
	*rsize = finSize;

	// Add in key by calling patchKey
	//TODO (maybe complete)
	//	patchKey(output, finSize, key);

	// Free any dynamically allocated memory
	// TODO (maybe complete)
	
	

	return TRUE;
}

int patchKey(uint8_t * data,uint32_t size,uint8_t * key) {
	// Add the key into the stub
	// TODO (don't have to)

	return TRUE;
}

int stubAddSection( uint32_t * rsize, uint8_t * stub, int sizeOfStub, PIMAGE_DOS_HEADER stubDosHeader) {
	// Fix up the stub PE header to include the extra section
	// add the input bytes to the end
	// TODO (maybe complete)
	// Note: this function will be a lot of work.

	// pe header --> SIGNATURE IS 50 45 (don't need)
	//PIMAGE_NT_HEADERS stubNTHeader = (PIMAGE_NT_HEADERS)((BYTE *)stubDosHeader + stubDosHeader->e_lfanew);

	//getting file header to calculate the amount of sections
	PIMAGE_FILE_HEADER stubFileHeader = (PIMAGE_FILE_HEADER)(stub + stubDosHeader->e_lfanew + sizeof(DWORD));

	//get optional header to add section (don't need at this moment)
	PIMAGE_OPTIONAL_HEADER stubOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(stub + stubDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	
	//get section header (not sure if its the start of first or end of last ---> seems like end of last)
	PIMAGE_SECTION_HEADER stubSectionHeader = (PIMAGE_SECTION_HEADER)(stub + stubDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	/*
	printf("[D] %d\n", stubFileHeader->NumberOfSections);
	printf("[D] %s\n", stubSectionHeader[stubFileHeader->NumberOfSections -1].Name);
	printf("[Section Align] %d\n", stubOptionalHeader->SectionAlignment);
	printf("[File Align] %d\n", stubOptionalHeader->FileAlignment);
	printf("[D] %x %x \n", stubSectionHeader[stubFileHeader->NumberOfSections - 1].VirtualAddress, stubSectionHeader[stubFileHeader->NumberOfSections - 1].Misc.VirtualSize);
	printf("[D] %x\n", stubSectionHeader[stubFileHeader->NumberOfSections - 1].VirtualAddress + stubSectionHeader[stubFileHeader->NumberOfSections - 1].Misc.VirtualSize);
	*/

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
	uint32_t * virtSize = rsize;
	while ((*virtSize % 4096) != 0)
	{
		*virtSize = *virtSize + 1;
	}
	stubSectionHeader[stubFileHeader->NumberOfSections - 1].Misc.VirtualSize = *virtSize;
	printf("\t[Misc.VirtualSize] %x\n", stubSectionHeader[stubFileHeader->NumberOfSections - 1].Misc.VirtualSize);
	

	// (2) set virtual address
	uint32_t virtAddress = stubSectionHeader[stubFileHeader->NumberOfSections - 2].VirtualAddress + stubSectionHeader[stubFileHeader->NumberOfSections - 2].Misc.VirtualSize;
	while ((virtAddress % 4096) != 0)
	{
		virtAddress++;
	}
	stubSectionHeader[stubFileHeader->NumberOfSections -1].VirtualAddress = virtAddress;
	printf("\t[Virt address] %x\n", virtAddress);
	
	
	// (3) set size of raw data
	uint32_t * rawSize = rsize;
	while ((*rawSize % 512) != 0)
	{
		*rawSize = *rawSize + 1;
	}
	stubSectionHeader[stubFileHeader->NumberOfSections - 1].SizeOfRawData= *rawSize;
	printf("\t[SizeOfRawData] %x\n", stubSectionHeader[stubFileHeader->NumberOfSections - 1].SizeOfRawData);


	// (4) set pointer to raw data
	uint32_t ptrToRaw = stubSectionHeader[stubFileHeader->NumberOfSections - 2].PointerToRawData + stubSectionHeader[stubFileHeader->NumberOfSections - 2].SizeOfRawData;
	stubSectionHeader[stubFileHeader->NumberOfSections-1].PointerToRawData = ptrToRaw;
	printf("\t[Pointer-to-raw-data] %x\n", ptrToRaw);

	// (5) setting the charachteristic for .ryanb (rwx)
	stubSectionHeader[stubFileHeader->NumberOfSections - 1].Characteristics = 0xE00000E0;

	// (6) setting the new size of image
	stubOptionalHeader->SizeOfImage = *rsize + sizeOfStub;

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
	/*
	printf("\t[D] Output Bytes:\n");

	for (size_t i = 0; i < *rsize; i++)
	{
		printf(" %02x",(*output)[i]);

	}
	*/
	return TRUE;
}

int inEncrypt(uint8_t ** buffer, int * rsize,uint8_t * key) {
	
	// Initialization
	aes256_context ctx;
	aes256_init(&ctx, key);

	// Pad the output before encryption
	uint8_t padCount = 16 - (*rsize % 16); // How many bytes to add 1 - 16
	printf("\t[+] Padding with %d bytes\n", padCount);

	//for (int i = 0; i < *rsize; i++)
	//{
	//	printf(" 0x%x", (*buffer)[i]);
	//}
	//printf("\n");

	*buffer = realloc(*buffer, *rsize + padCount);

	// Zero out new space
	for (int i = *rsize; i < padCount+*rsize; i++)
	{
		(*buffer)[i] = 0;
	}

	// set size to new value
	*rsize = *rsize + padCount;
	printf("\t[+] Buffer size is now %d bytes\n", *rsize);

	//// Store the pad count as the last byte
	(*buffer)[(*rsize)-1] = padCount;

	//// debug
	//printf("\t\tDebug\n");
	//printf("\t\t&buffer %x\n", (uint32_t)(&buffer));
	//printf("\t\tbuffer %x\n", (uint32_t)(buffer));
	//printf("\t\t*buffer %x\n", (uint32_t)(*buffer));
	//printf("\t\t**buffer %x\n", (uint32_t)(**buffer));
	//for (int i = 0; i < *rsize; i++)
	//{
	//	printf(" 0x%x", (*buffer)[i]);
	//}
	//printf("\n");

	// Need to break into 16 byte chunks
	for (int i = 0; i < *rsize / 16; i++)
	{
		aes256_encrypt_ecb(&ctx, (*buffer)+(i*16));
	}

	//for (int i = 0; i < *rsize; i++)
	//{
	//	printf(" 0x%x", (*buffer)[i]);
	//}
	//printf("\n");

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


// Functions to encrypt
//void aes256_init(aes256_context *, uint8_t * /* key */);
//void aes256_done(aes256_context *);
//void aes256_encrypt_ecb(aes256_context *, uint8_t * /* plaintext */);
//void aes256_decrypt_ecb(aes256_context *, uint8_t * /* cipertext */);
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

