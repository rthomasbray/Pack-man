#pragma once
#include <stdio.h>
#include <Windows.h>
#include "Shlwapi.h"
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include "aes.h"
#include <Psapi.h>
#include <compressapi.h>
#include "loader.h"

#define KEY_LEN 32
#define MAGIC_KEY 0x4e4e4e4e
#define MAGIC_SIZE 0x69696969
#define MAGIC_ADDR 0x31323334
/*
Description: 
The decompress function takes in a double pointer to a buffer containing compressed data

Parameters:
[IN/OUT] buffer - buffer to compressed data. Comes back uncompressed
[IN/OUT] size - pointer to an int containing the size. Updated on return

Return:
True on success
False on failure
*/
int decompress(uint8_t ** buffer, uint32_t * size);

/*
Description:
The decrypt function takes in a double pointer to a buffer containing encrypted data

Parameters:
[IN/OUT] buffer - buffer to encrypted data. Comes back decrypted
[IN/OUT] size - pointer to an int containing the size. Updated on return
[IN] key - pointer to an array containing the key. 

Return:
True on success
False on failure
*/
int decrypt(uint8_t ** buffer, int * rsize, uint8_t * key);
