#pragma once

#include <stdio.h>
#include <Windows.h>
#include "Shlwapi.h"
#include <stdlib.h>
#include <stdint.h>
#include "pack.h"

#define KEY_LEN 32

// Get the command line arguments
int getArgs(int argc, char ** argv, char * path);

// Print the usage statement
void printUsage();