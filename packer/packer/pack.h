#pragma once
#include <stdint.h>
#include <Windows.h>
#include <wincrypt.h>
#include <compressapi.h>
#include "aes.h"
#include "packer.h"

/*
Description:
Adds a key to the binary to be output

Parameters:
[IN/OUT] data - The buffer for the key to be added to
[IN] size - The size of the buffer
[IN] key - a randomly generated aes256 key as bytes
*/
int patchKey(uint8_t * data, uint32_t size, uint8_t * key);

/*
Description:
Encrypts the file bytes using AES256

Parameters:
[IN/OUT] buffer - The buffer to be encrypted
[IN/OUT] rsize - The size of the buffer
[IN] key - a randomly generated aes256 key as bytes
*/
int inEncrypt(uint8_t ** buffer, int * rsize,uint8_t * key);

/*
Description:
Compresses the input buffer using the xpress compression algorithm

Parameters:
[IN] input - The file bytes read in from the file
[OUT] output - The packed binary output
[IN/OUT] rsize - The size of the output buffer
[IN] insize - The size of the input buffer
*/
int inCompress(uint8_t * input, int insize, uint8_t ** output, int * rsize);

/*
Description: 
Generates a self-unpacking output exe as a byte stream.

Parameters:
[IN] input - The file bytes read in from the file
[OUT] output - The packed binary output
[IN] key - a randomly generated aes256 key as bytes
[IN/OUT] rsize - The size of the output buffer
[IN] insize - The size of the input buffer 
*/
int pack(uint8_t * input, uint8_t ** output, uint8_t * key, uint32_t * rsize,uint32_t insize);

/*
Description:
Adds the encrypted and compressed input file as a section to the stub

Parameters:
[IN/OUT] dataBuffer - The encrypted and compressed input binary. The Output goes here. 
[IN/OUT] rsize - The size of the inputData buffer. Updated to the size of dataBuffer.
[IN] stub - The bytes of the stub
[IN] sizeOfStub - The size of the stub
[IN] sections - The sections of the binary. Will be examined to find last section.
[IN] stubPE - The PE structure of the stub
*/
int stubAddSection(uint8_t ** dataBuffer, uint32_t * rsize, uint8_t * stub, int sizeOfStub, IMAGE_NT_HEADERS * sections,IMAGE_NT_HEADERS stubPE);

/*
Description:
Tests that the compression library is working correctly

Parameters:
[IN] input - The file bytes read in from the file
[IN] insize - The size of the input buffer
*/
int testCompress(uint8_t * input, size_t insize);

/*
Description:
Tests that the Aes library is working correctly

Parameters:
[IN] key - a randomly generated aes256 key as bytes
*/
int testAes(uint8_t * key);