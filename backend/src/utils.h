
/*-----------------------------------------------------------------------*/
/* Code file: utils.h                                                    */
/*-----------------------------------------------------------------------*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "color_codes.h"

//	error handler
void die(const char *format, ...);

//	appends text to an already allocated string
void append(char **dest, const char *src);

//	generates a string from the time instant in which the function is called
const char *getTimestamp(void);

//	32-bit int to 16char string IP converter
char *smart_IP_to_char(int addr);
