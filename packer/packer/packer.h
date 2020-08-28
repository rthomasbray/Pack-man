#pragma once

#include <stdio.h>
#include <Windows.h>
#include "Shlwapi.h"
#include <stdlib.h>
#include <stdint.h>
#include "pack.h"

#define KEY_LEN 32

// testing values
#define MAGIC_KEY 0x4e4e4e4e
#define MAGIC_SIZE 0x69696969
#define MAGIC_ADDR 0x31323334

// Get the command line arguments
int getArgs(int argc, char ** argv, char * path);

// Print the usage statement
void printUsage();