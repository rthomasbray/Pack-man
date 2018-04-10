#include "loader.h"


int loader(uint8_t * data)
{
	// Get information from PE headers

	// Get sections from PE image

	// Reserve memory for program
	// Attempt to get prefered base address. If cannot calculate offset.


	// Load sections from the sections table into memory


	// Perform relocations


	// Handle the imports in the imports table here


	// Jump to entry point of the program
	//Cast entry point address to function

	 
	// free any dynamically allocated memory

	return FALSE;
}
