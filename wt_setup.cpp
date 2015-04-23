#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>

#include "wt_setup.h"

/**
 * usage(FILE * file) -> void
 *
 * Write the usage info for wiretap to the given file pointer.
 */

void usage(FILE * file){
  if(file == NULL){
     file = stdout;
  }

  fprintf(file,
         "Wiretap [OPTIONS] \n"
         "\t --help                 \t\t Print this help screen\n"
         "\t --open capture_file    \t\t Open a specified file\n"
         );
}

/**
 * parse_args(char *captureFile, int argc,  char * argv[]) -> void
 *
 * Parses the input arguments.
 **/

void parse_args(char *captureFile, int argc,  char * argv[]) {
  //Check for --help option
  if((argc == HELP_ARGS) && (strcmp(argv[1], "--help") == 0)) {
	usage(stdout);
	exit(EXIT_SUCCESS);
  }
  //Check for --open option
  else if ((argc == OPEN_ARGS) && (strcmp(argv[1], "--open") == 0)) {
	strcpy(captureFile, argv[2]);
  }
  //Prints the help menu of there is an error in input arguments
  else {
    usage(stderr);
	exit(EXIT_FAILURE);
  }
}