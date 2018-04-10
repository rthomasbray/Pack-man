#include "packer.h"

int main(int argc, char ** argv) {
	char exe_file_path[MAX_PATH] = { 0 };
	char out_file_path[MAX_PATH] = {0};
	uint8_t key[KEY_LEN];


	// Check that the correct arguments were provided to the program
	// If incorrect arguments were provided then print usage statement and exit
	if (!getArgs(argc, argv, exe_file_path)) {
		printUsage();
		return FALSE;
	}

	// Generate a key to encrypt with
	// Lame version: just create a static key
	// Cool version: generate a random key
	// TODO

	// Get the file bytes from the input file
	// Filename is stored in exe_file_path
	// TODO

	// Pass key and input file bytes to the pack function
	// Pack function is inside pack.c
	// TODO

	// Create output path
	// TODO

	// Write to output file
	// TODO
	
	// Close output file 
	// TODO

	// Free dynamically allocated memory
	// TODO
}
// Prints the usage information for the packer
void printUsage() {
	printf("Usage: \"packer.exe exe_file_to_pack\"\n");
}
// parser the packer arguments
int getArgs(int argc,char ** argv, char * path) {
	if (argc != 2) {
		return FALSE;
	}
	//printf("copy path\n");
	//Copy file path
	strncpy_s(path,MAX_PATH,argv[1], MAX_PATH);

	//printf("check path\n");
	// Make sure the file path exists
	if(!PathFileExists(path)){
		printf("The file does not exist!\n");
		return FALSE;
	}
	else {
		return TRUE;
	}


	return TRUE;
}
