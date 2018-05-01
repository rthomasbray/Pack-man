#include "main.h"

uint32_t flag = 0x31323334;

int main() {
	// To mark the start
	printf("Hello World from the stub2\n"); 
	
	uint8_t * buffer =(uint8_t *)&flag;
	uint32_t bufferSize = 5088;
	printf("[E&C TEST BYTE] %x\n", *(buffer));
	printf("[E&C TEST BYTE] %x\n", *(buffer + 1));
	printf("[E&C TEST BYTE] %x\n", *(buffer+5086));
	printf("[E&C TEST BYTE] %x\n", *(buffer+5087));

	//Same key as in packer
	uint8_t key[KEY_LEN] = { 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f' };

	// Decrypt the data - See function below
	printf("[+] Decrypting\n");
	decrypt(&buffer, &bufferSize, key);
	printf("[+] Decrypting complete\n");

	printf("[FIN TEST BYTE] %x\n", *(buffer));
	printf("[FIN TEST BYTE] %x\n", *(buffer + 1));
	printf("[FIN TEST BYTE] %x\n", *(buffer + 2));

	// Decompress the data - see function below
	printf("[+] Decompressing\n");
	decompress(&buffer, &bufferSize);
	printf("[+] Decompression complete\n");

	printf("[f TEST BYTE] %x\n", *(buffer));
	printf("[f TEST BYTE] %x\n", *(buffer + 1));
	printf("[f TEST BYTE] %x\n", *(buffer + 2));
	printf("[f TEST BYTE] %x\n", *(buffer + 0x860));

	// Pass data into loader function
	printf("[+] Passing to loader\n");
	loader(buffer);
	printf("[+] Loading complete\n");

	

	return TRUE;

}

int decompress(uint8_t ** buffer,uint32_t * size) {
	//printf("[D] Buffer recv by decompress was: \n");
	//for (size_t i = 0; i < *size; i++)
	//{
	//	printd(" %02x", (*buffer)[i]);
	//}
	
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
	//free(*buffer);

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
	//*buffer = realloc(*buffer, *rsize);
	//*buffer = realloc(*buffer, *rsize);

	printf("\t[+] Decryption Finished\n");


	return TRUE;
}