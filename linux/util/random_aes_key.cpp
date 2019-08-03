//
// Created by timber3252 on 7/21/19.
//

#include <cstdio>
#include <cstring>
#include <random>
#include <cstdint>

#include <unistd.h>

int main(int argc, char *argv[]) {
  int ch, length = 128;
  char outfile[FILENAME_MAX] = "output.key";
  while ((ch = getopt(argc, argv, "hl:")) != -1) {
    switch (ch) {
      case 'l': {
        length = atoi(optarg);
        if (length != 128 && length != 192 && length != 256) {
          printf("Invalid length %d\n", length);
          return -1;
        }
        break;
      }
      case 'f': {
        strcpy(outfile, optarg);
        break;
      }
      case 'h': {
        printf(
            "Usage: %s arguments ..                             \n"
            "  -h             show help                         \n"
            "  -f filename    output file                       \n",
            argv[0]);
        return 0;
      }
    }
  }
  std::default_random_engine e(srand(nullptr));
  std::uniform_int_distribution<uint8_t> gen(0x00, 0xff);
  uint8_t *res = new uint8_t[length];
  for (int i = 0; i < length; ++i) {
    res[i] = gen(e);
  }
  FILE *fp = fopen(outfile, "w");
  fwrite(fp, sizeof(uint8_t), length, fp);
  return 0;
}