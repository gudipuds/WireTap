#ifndef _BT_SETUP_H
#define _BT_SETUP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>

#include "wt_setup.h"

//Number of input arguments for 'help' option
#define HELP_ARGS 2

//Number of input arguments for 'open' option
#define OPEN_ARGS 3

/**
 * parse_args(char *captureFile, int argc,  char * argv[]) -> void
 *
 * Parses the input arguments.
 **/
void parse_args(char *captureFile, int argc,  char * argv[]);

/**
 * parse_args(char *captureFile, int argc,  char * argv[]) -> void
 *
 * Parses the input arguments.
 **/
void parse_args(char *captureFile, int argc,  char * argv[]);

#endif