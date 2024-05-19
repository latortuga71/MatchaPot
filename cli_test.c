#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  printf("Hello From CoffePot!\n");
  argv++;
  char *path = *argv;
  printf("%s \n", path);
  FILE *fptr = fopen(path, "r");
  if (fptr == NULL) {
    fprintf(stderr, "Failed to open %s\n", path);
    return -1;
  }
  fseek(fptr, 0, SEEK_END);
  long file_size = ftell(fptr);
  rewind(fptr);
  printf("File Size is %lu \n", file_size);
  char *buffer = (char *)malloc(sizeof(char) * file_size);
  fread(buffer, 1, file_size, fptr);
  if (buffer[0] == 'A') {
    if (buffer[1] == 'B') {
      if (buffer[2] == 'C') {
        if (buffer[3] == 'D') {
          if (buffer[4] == 'E') {
            if (buffer[5] == 'F') {
              if (buffer[6] == 'G') {
                if (buffer[7] == 'H') {
                  if (buffer[8] == 'I') {
                    if (buffer[9] == 'J') {
                      if (buffer[10] == 'K') {
                        if (buffer[11] == 'L') {
                          int crash = *(int *)0xFFF2351F;
                          printf("crash");
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  free(buffer);
  return 0;
}
