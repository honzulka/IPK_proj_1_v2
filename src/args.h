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

int parse_args(int argc, char **argv, args_t *args);
void print_usage(void);

#endif
