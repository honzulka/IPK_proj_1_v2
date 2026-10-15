/**
 * @file args.h
 * @brief Command-line argument parsing
 */

#ifndef ARGS_H
#define ARGS_H

#define MAX_SUBNETS 32

typedef struct {
  char *interface;
  char *subnets[MAX_SUBNETS];
  int subnet_count;
  int timeout_ms;
  int help;
  int list_interfaces;
} args_t;

/**
 * @brief Parse command-line arguments into @ref args_t.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param args Output structure.
 * @return 0 on success, -1 on invalid arguments.
 */
int parse_args(int argc, char **argv, args_t *args);

/**
 * @brief Print CLI usage to stdout.
 */
void print_usage(void);

#endif
