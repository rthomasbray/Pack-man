#include "main.h"

uint32_t flag = MAGIC_ADDR;
uint8_t key[32] = {MAGIC_KEY,MAGIC_KEY,MAGIC_KEY,MAGIC_KEY };
uint32_t bufferSize =MAGIC_SIZE;


int main() 
{
	
	// first anti debug technique
	__asm
	{
		push ss
		pop  ss
		pushfd
		test[esp + 1], 1
		jne  DBG_Dest
	}


	// second anti debug technique
	__asm
	{
		xor eax, eax
		push offset DBG_Dest
		push fs : [eax]
		mov fs : [eax], esp
		call CloseHandle
	}
	

	//getting pointer to .ryanb
	uint8_t * buffer =(uint8_t *)&flag;

	//creating new buffer to deal with change in size
	uint8_t * newBuff = malloc(bufferSize);
	memcpy(newBuff, buffer, bufferSize);


	
	//getting pointer to decryption key
	for (size_t i = 0; i < 32; i++)
	{
		printf("%c", key[i]);
	}
	printf("\n");
	
	// this was used before "random" key gen
	//Same key as in packer
	//uint8_t key[KEY_LEN] = { 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f' };

	// Decrypt the data - See function below
	printf("[+] Decrypting\n");
	decrypt(&newBuff, &bufferSize, key);
	printf("[+] Decrypting complete\n");

	// Decompress the data - see function below
	printf("[+] Decompressing\n");
	decompress(&newBuff, &bufferSize);
	printf("[+] Decompression complete\n");

	// Pass data into loader function
	printf("[+] Passing to loader\n");
	loader(newBuff);
	printf("[+] Loading complete\n");

	return TRUE;

DBG_Dest:
	printf("Is that a debugger you have there?!");
	exit(0);
	return FALSE;

}

int decompress(uint8_t ** buffer,uint32_t * size) {
	
	COMPRESSOR_HANDLE Decompressor = NULL;
	BOOL Success;
	SIZE_T DecompressedBufferSize, DecompressedDataSize;
	uint8_t * DecompressedBuffer;

	//  Create an Xpress decompressor.
	Success = CreateDecompressor(
		COMPRESS_ALGORITHM_XPRESS, //  Compression Algorithm
		NULL,                           //  Optional allocation routine
		&Decompressor);                   //  Handle

	Success = Decompress(
		Decompressor,                //  Compressor Handle
		*buffer,            //  Compressed data
		*size,               //  Compressed data size
		NULL,                        //  Buffer set to NULL
		0,                           //  Buffer size set to 0
		&DecompressedBufferSize);    //  Decompressed Data size

	DecompressedBuffer = (PBYTE)malloc(DecompressedBufferSize);

	Success = Decompress(
		Decompressor,               //  Decompressor handle
		*buffer,           //  Compressed data
		*size,              //  Compressed data size
		DecompressedBuffer,         //  Decompressed buffer
		DecompressedBufferSize,     //  Decompressed buffer size
		&DecompressedDataSize);     //  Decompressed data size

	if (!Success)
	{
		printf("[-] Cannot decompress data: %d.\n", GetLastError());
		free(*buffer);
		exit(0);
	}

	printf("\t[+] Decompressed Size:%d\n", DecompressedDataSize);

	//did not use malloc or calloc so this is no longer needed
	free(*buffer);

	*buffer = DecompressedBuffer;
	*size = DecompressedBufferSize;

	CloseDecompressor(Decompressor);

	return TRUE;
}

int decrypt(uint8_t ** buffer, int * rsize, uint8_t * key) {
	// Initialization
	aes256_context ctx;
	aes256_init(&ctx, key);

	// Need to break into 16 byte chunks
	for (int i = 0; i < *rsize / 16; i++)
	{
		aes256_decrypt_ecb(&ctx, (*buffer) + (i * 16));
	}

	aes256_done(&ctx);

	//// Get the last byte which is the padding
	uint32_t padCount = (*buffer)[(*rsize) - 1];
	printf("\t[+] Removing %d bytes of padding\n", padCount);


	// set size to new value
	*rsize = *rsize - padCount;
	printf("\t[+] New Size %d bytes\n", *rsize);

	//did not use malloc or calloc so this is no longer needed
	*buffer = realloc(*buffer, *rsize);

	printf("\t[+] Decryption Finished\n");


	return TRUE;
}