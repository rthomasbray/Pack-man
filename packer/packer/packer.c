#include "packer.h"

int main(int argc, char ** argv) {
	char exe_file_path[MAX_PATH] = "C://Users/Ryan Thomas Bray/Desktop/packer/Debug/calc_pi.exe";
	char out_file_path[MAX_PATH] = "C://Users/Ryan Thomas Bray/Desktop/packer/Debug/test.exe";
	uint8_t key[KEY_LEN] = { 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f' };

	// Check that the correct arguments were provided to the program
	// If incorrect arguments were provided then print usage statement and exit

	
	if (!getArgs(argc, argv, exe_file_path)) {
		printUsage();
		return FALSE;
	}
	
	// Generate a key to encrypt with
	// Lame version: just create a static key
	// Cool version: generate a random key
	// TODO (maybe completed)
	// for now opting for lame;  is intialized above..
	printf("\n\n[+] Generating key\n");

	// Get the file bytes from the input file
	// Filename is stored in exe_file_path
	// TODO (completed)
	//get file pointer
	FILE * inputFilePointer = fopen(exe_file_path, "rb");
	//get the end of file
	fseek(inputFilePointer, 0, SEEK_END);
	//calculate the offset
	uint32_t inputFileLength = ftell(inputFilePointer);
	// revert the file pointer to the begining 
	rewind(inputFilePointer);
	//allocate space for fileBuffer
	uint8_t * inputFileBuffer = (uint8_t *)malloc(inputFileLength);
	//read in file to fileBuffer
	fread(inputFileBuffer, inputFileLength, 1, inputFilePointer);
	//close input file
	fclose(inputFilePointer);
	
	// Pass key and input file bytes to the pack function
	// Pack function is inside pack.c
	// TODO (complete)
	uint8_t * outputBuffer = malloc(100);
	uint32_t outputSize = 100;

	//pack(uint8_t * input, uint8_t ** output, uint8_t * key, uint32_t * rsize, uint32_t insize)
	pack(inputFileBuffer, &outputBuffer, key, &outputSize , inputFileLength);
	printf("[+] Packing complete\n");

	// Create output path
	// TODO (complete)
	printf("[+] Opening file\n");
	FILE * outputFilePointer;
	outputFilePointer = fopen("test.exe", "wb");
	//printf("%x\n", outputFilePointer);


	// Write to output file
	// TODO (complete)
	printf("[+] Writing to file\n");
	printf("[D] File size: %d\n", outputSize);
	fwrite(outputBuffer, outputSize, 1 , outputFilePointer);
	

	// Close output file 
	// TODO (complete)
	printf("[+] Closing file\n");
	fclose(outputFilePointer);

	// Free dynamically allocated memory
	// TODO (complete)
	printf("[+] Freeing memory and leaving packer\n");
	free(inputFileBuffer);
	free(outputBuffer);
	

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
