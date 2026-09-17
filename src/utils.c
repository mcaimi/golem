
/*-----------------------------------------------------------------------*/
/* Code file: utils.c                                                    */
/*-----------------------------------------------------------------------*/

#include "utils.h"

/*
 * die():
 * HARAKIRI
 */
void die(const char *format, ...) {
  //	container for the list of the arguments passed to the function
  va_list argument_list;

  fflush(stdout);
  fprintf(stderr, "%s %s %s %s %s %s %s", PURPLE, " .::APPLICATION SUICIDE::. ",
          RED, "(", getTimestamp(), ")", RESET);
  fprintf(stderr, "%s %s", YELLOW, " [FATAL ERROR:] ");
  va_start(argument_list, format);
  vfprintf(stderr, format, argument_list);
  va_end(argument_list);
  printf(RESET);
  exit(-1);
}

/*
 * append():
 * Appends text to a char string, expanding it as necessary
 */
void append(char **dest, const char *src) {
  int len, number_of_bytes;

  if (src == NULL)
    return;

  if (*dest == NULL)
    len = 0;
  else
    len = strlen(*dest);

  //	compute the new length of the string
  number_of_bytes = len + strlen(src) + 1;

  if (*dest != NULL) {
    //	allocating space beyond the end of the old string
    *dest = (char *)realloc(*dest, number_of_bytes);
    if (*dest == NULL) {
      die("utils.c[append()]: OUT OF MEMORY: realloc() failed");
    }
  } else {
    //	create a new string
    *dest = (char *)malloc(number_of_bytes);
    if (*dest == NULL) {
      die("utils.c[append()]: OUT OF MEMORY: realloc() failed");
    }
  }

  strcpy(*dest + len, src);
}

/*
 * Appends a string to another one
 */

char *smart_append(char *string_to_add) {
  char *tmp;

  append(&tmp, string_to_add);

  return (char *)tmp;
}

/*
 * IP_to_char(): (smarter WORKING version)
 * it converts a 32-bit integer into the corresponding IP address string with
 * the aid of a lookup table
 */
char *smart_IP_to_char(int addr) {
  const char lookup_table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
                               '9', '0', 'A', 'B', 'C', 'D', 'E', 'F'};
  int x, i = 3;
  char *s;
  s = (char *)malloc(16);
  if (s == NULL)
    die("IP_to_char(): malloc(): OUT OF MEMORY\n");
  memset(s, 0, (16 * sizeof(char)));
  //	too lazy to comment...
  while (i >= 0) {
    x = (addr >> (8 * i)) & 0xff;
    int cypher = (int)(x % 10);
    x /= 10;
    *(s + (4 * (3 - i)) + 2) = lookup_table[cypher];
    cypher = (int)(x % 10);
    x /= 10;
    *(s + (4 * (3 - i)) + 1) = lookup_table[cypher];
    cypher = (int)(x % 10);
    x /= 10;
    *(s + (4 * (3 - i))) = lookup_table[cypher];
    // DOT in xxx.yyy.zzz.kkk
    *(s + (4 * (3 - i)) + 3) = '.';
    --i;
  }
  *(s + 0x0f) = '\0';
  return (char *)s;
}

/*
 * getTimestamp():
 * generates a string containing the time stamp of the instant in which this
 * function is called
 */
const char *getTimestamp(void) {
  static char ret[32];
  struct tm *tm;
  //	time container structure
  time_t t;

  time(&t);
  //	get the actual data from the system
  tm = localtime(&t);

  //	convert to a cool string
  strftime(ret, sizeof(ret), "%Y-%m-%d_%H:%M:%S", tm);
  ret[sizeof(ret) - 1] = '\0';
  return ret;
}
