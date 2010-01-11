// Load default settings
#include "defaults.h"

// A structure that contains information about a specific type of exception.
struct exception_description {
  DWORD code;                           // The exception code used to identify this exception.
  char* short_name;                     // The (short) name of this type of exception.
  char* description;                    // An (optional) description of the problem. Use NULL if there is none.
};
// A list containing information about all kinds of known exceptions:
struct exception_description exception_descriptions[] = {
#define exception_description_av (exception_descriptions[0])
    {EXCEPTION_ACCESS_VIOLATION, "access violation", NULL},
    {EXCEPTION_ARRAY_BOUNDS_EXCEEDED, "array out of bounds", 
        "Attempt to access an element outside the bounds of an array."},
    {EXCEPTION_BREAKPOINT, "debugger breakpoint", NULL},                        // Should be obvious
    {EXCEPTION_DATATYPE_MISALIGNMENT, "data misaligned", 
        "Attempt to access misaligned data."},
    {EXCEPTION_FLT_DENORMAL_OPERAND, "denormal floating-point operand", 
        "Attempt to execute a floating-point operation with a too small operand."},
    {EXCEPTION_FLT_DIVIDE_BY_ZERO, "floating-point divide by zero", NULL},      // Should be obvious
    {EXCEPTION_FLT_INEXACT_RESULT, "inexact floating-point result", 
        "The result of a floating-point operation cannot be represented exactly as a decimal fraction."},
    {EXCEPTION_FLT_INVALID_OPERATION, "invalid floating-point operation", 
        "Unspecified invalid floating point operation."},
    {EXCEPTION_FLT_OVERFLOW, "floating-point overflow", 
        "The result of a floating-point operation is too large to be stored."},
    {EXCEPTION_FLT_STACK_CHECK, "floating-point stack", 
        "The stack overflowed or underflowed as the result of a floating-point operation."},
    {EXCEPTION_FLT_UNDERFLOW, "floating-point underflow", 
        "The result of a floating-point operation is too small to be stored."},
    {EXCEPTION_ILLEGAL_INSTRUCTION, "illegal instruction", NULL},               // Should be obvious
    {EXCEPTION_IN_PAGE_ERROR, "memory paging", 
        "Attempt to access paged memory that cannot be loaded."},
    {EXCEPTION_INT_DIVIDE_BY_ZERO, "integer divide by zero", NULL},             // Should be obvious
    {EXCEPTION_INT_OVERFLOW, "integer overflow", 
        "The result of an integer operation is too large to be stored."},
    {EXCEPTION_INVALID_DISPOSITION, "invalid handler disposition",
        "An exception handler returned an invalid disposition to the exception dispatcher."},
    {EXCEPTION_NONCONTINUABLE_EXCEPTION, "noncontinuable", 
        "Attempt to continue execution after a noncontinuable exception occurred."},
    {EXCEPTION_PRIV_INSTRUCTION, "privileged instruction", NULL},               // Should be obvious
    {EXCEPTION_SINGLE_STEP, "single step", 
        "A trace trap or other single-instruction mechanism signaled that one instruction has been executed."},
    {EXCEPTION_STACK_OVERFLOW, "stack overflow", 
        "The thread exhausted all available stack memory."}
};
#define exception_descriptions_count (sizeof(exception_descriptions) / sizeof(struct exception_description))
// Show information about an exception based on a PEXCEPTION_POINTERS structure:
void show_exception_information(char* exception_type, PEXCEPTION_POINTERS exception_pointers) {
  int i;
  DWORD exception_code = exception_pointers->ExceptionRecord->ExceptionCode;
  VALUE exception_address = (VALUE)exception_pointers->ExceptionRecord->ExceptionAddress;
  // Access violation exceptions are handled separately:
  if (exception_code == EXCEPTION_ACCESS_VIOLATION) {
    // The ExceptionInformation tells us what type of access (read, write, execute) was attempted and at what 
    // address was accessed:
    VALUE access_type = (VALUE)exception_pointers->ExceptionRecord->ExceptionInformation[0];
    VALUE access_address = (VALUE)exception_pointers->ExceptionRecord->ExceptionInformation[1];
    // Execute AVs van be masked as read AVs, in this case the exception address is the same as the access address:
    if (access_type == 0 && access_address != exception_address) {
      fprintf(stderr, "%s %s while reading from [" FMT_VAL "] at " FMT_VAL ".\r\n", 
          exception_type, exception_description_av.short_name, access_address, exception_address);
    } else if (access_type == 1) {
      // The memory may not be writeable, in that case it should be possible to read it:
      if (IsBadReadPtr((PVOID)access_address, 1)) {
        // Memory cannot be read either: there must be no memory allocated at that address:
        fprintf(stderr, "%s %s while writing to [" FMT_VAL "] at " FMT_VAL ": no memory allocated.\r\n", 
            exception_type, exception_description_av.short_name, access_address, exception_address);
      } else {
        // Memory can be read, so it must be read-only:
        fprintf(stderr, "%s %s while writing to [" FMT_VAL "] at " FMT_VAL ": memory is read-only.\r\n", 
            exception_type, exception_description_av.short_name, access_address, exception_address);
      }
    } else if (access_type == 8 || (access_type == 0 && access_address == exception_address)) {
      // The memory may not be executable (DEP), in that case it should be possible to read it:
      if (IsBadReadPtr((PVOID)access_address, 1)) {
        // Memory cannot be read either: there must be no memory allocated at that address:
        fprintf(stderr, "%s %s while executing [" FMT_VAL "]: no memory allocated.\r\n", 
            exception_type, exception_description_av.short_name, exception_address);
      } else {
        // Memory can be read, so it must not be executable:
        fprintf(stderr, "%s %s while executing [" FMT_VAL "]: memory is non-executable.\r\n", 
            exception_type, exception_description_av.short_name, exception_address);
      }
    } else {
      // This is highly unlikely to happen!
      if (IsBadReadPtr((PVOID)access_address, 1)) {
        fprintf(stderr, "%s %s while accessing [" FMT_VAL "] at " FMT_VAL ": no memory allocated.\r\n", 
            exception_type, exception_description_av.short_name, access_address, exception_address);
      } else {
        fprintf(stderr, "%s %s while accessing [" FMT_VAL "] at " FMT_VAL ": memory is protected.\r\n", 
            exception_type, exception_description_av.short_name, access_address, exception_address);
      }
    }
  } else {
    for (i = 0; i < exception_descriptions_count; i++) {
      if (exception_code == exception_descriptions[i].code) {
        char* short_name = exception_descriptions[i].short_name;
        char* description = exception_descriptions[i].description;
        if (description == NULL) {
          fprintf(stderr, "%s %s exception at " FMT_VAL ".\r\n", 
              exception_type, short_name, exception_address);
        } else {
          fprintf(stderr, "%s %s exception at " FMT_VAL ": %s\r\n", 
              exception_type, short_name, exception_address, description);
        }
        break;
      }
    }
    if (i == exception_descriptions_count) {
      fprintf(stderr, "%s exception 0x%08X at " FMT_VAL ".\r\n", 
          exception_type, exception_code, exception_address);
    }
  }
}

// Display information about all exceptions but do not handle them:
LONG CALLBACK vectored_exception_handler(PEXCEPTION_POINTERS exception_pointers) {
  show_exception_information("First chance", exception_pointers);
  return EXCEPTION_CONTINUE_SEARCH;
}
// Display information about an unhandled exception and terminate the application with exit code 1.
LONG WINAPI unhandled_exception_filter(PEXCEPTION_POINTERS exception_pointers) {
  show_exception_information("Second chance", exception_pointers);
  // If this is anything but a debug breakpoint, terminate the application:
  if (exception_pointers->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
    exit(1);
  }
  // If this is a debug breakpoint, let it through so the user can debug the application:
  return EXCEPTION_CONTINUE_SEARCH;
}
