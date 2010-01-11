#ifndef _defaults_h_
  #define _defaults_h_
  // Target Windows 5.0 and up (Windows 2000). Required to be able to use VEH.
  #define WINVER 0x0500
  #define _WIN32_WINNT 0x0500
  // Include required header files:
  #include <windows.h>
  #include <string.h>
  #include <stdio.h>
  #include <excpt.h>
  // Architectures specific settings:
  #ifdef _WIN64
    #define VALUE_BITS 64                 // Values are 64-bit
    typedef DWORD64 VALUE;                // The 64-bit type of a VALUE
    #define FMT_VAL "%016X"               // Value format string
    #define STR_TO_VAL(x,y,z) ((VALUE) _strtoui64(x,y,z)) // Converts number in string to 64-bit value
    #define VALUE_MAX_SIGNED 0x7FFFFFFFFFFFFFFF // Maxium value of unsigned 64-bit integer.
  #else
    #define VALUE_BITS 32                 // Values are 32-bit
    typedef DWORD VALUE;                  // The 32-bit type of a VALUE
    #define FMT_VAL "%08X"                // Value format string
    #define STR_TO_VAL(x,y,z) ((VALUE) strtoul(x,y,z)) // Converts number in string to 32-bit value
    #define VALUE_MAX_SIGNED 0x7FFFFFFF   // Maxium value of unsigned 32-bit integer.
  #endif
  // Used to QUOTE defined values.
  #define _QUOTE(x) #x
  #define QUOTE(x) _QUOTE(x)
#endif
