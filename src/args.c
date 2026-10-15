/**
 * @file args.c
 * @brief Implementation of command-line parsing.
 */

#include "args.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void print_usage(void) {
  printf("Usage:\n");
  printf("  ./ipk-L2L3-scan -i INTERFACE [-s SUBNET]... [-w TIMEOUT]\n");
  printf("  ./ipk-L2L3-scan -i\n");
  printf("  ./ipk-L2L3-scan -h | --help\n");
}

int parse_args(int argc, char **argv, args_t *args) {
  memset(args, 0, sizeof(args_t));

  if (argc <= 1) {
    fprintf(stderr, "No arguments were given\n");
    return -1;
  }

  args->timeout_ms = 1000;

  for (int i = 1; i < argc; i++) { // start from 1 (argv[0] is program)
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      args->help = 1;
      return 0;
    } else if (strcmp(argv[i], "-i") == 0) {
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        args->interface = argv[++i];
      } else {
        args->list_interfaces = 1;
      }
    } else if (strcmp(argv[i], "-s") == 0) {
        if (i + 1 >= argc) {
          fprintf(stderr, "Missing value for -s\n");
          return -1;
        }
        if (args->subnet_count >= MAX_SUBNETS) {
          fprintf(stderr, "Too many subnets\n");
          return -1;
        }
        args->subnets[args->subnet_count++] = argv[++i];
    } else if (strcmp(argv[i], "-w") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Missing value for -w\n");
        return -1;
      }
      args->timeout_ms = atoi(argv[++i]);
      if (args->timeout_ms == 0) {
        fprintf(stderr, "Could not convert given timeout to integer");
        return -1;
      }
    } else {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      return -1;
    }
  }

  if (!args->help && !args->list_interfaces && args->interface == NULL) {
    fprintf(stderr, "Interface must be specified\n");
    return -1;
  }

  return 0;
}
