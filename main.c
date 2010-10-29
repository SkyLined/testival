// Copyright (c) 2006-2010, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
// Project homepage: http://code.google.com/p/testival/
// All rights reserved. See COPYRIGHT.txt for details.

// Load default settings
#include "defaults.h"

//______________________________________________________________________________________________________________________
//                                                                                                                      
//                                         : win-shellcode-tester - Windows shellcode/ret-into-libc testing tool        
//                                         :                                                                            
//                                         : Copyright (C) 2006-2009 by SkyLined.                                       
//                                         : <berendjanwever@gmail.com>                                                 
//                                         : http://skypher.com/wiki/index.php/Shellcode                                
//______________________________________________________________________________________________________________________
//                                                                                                                      


// Include external assembler code required to set all registers, including ESP/RSP and EIP/RIP:
extern void asm_SetRegisters(VALUE *pregisters, BOOL do_int3, BOOL do_ret, BOOL set_sp, BOOL set_ip);
// Include external exception handling code:
extern LONG CALLBACK vectored_exception_handler(PEXCEPTION_POINTERS exception_pointers);
extern LONG WINAPI unhandled_exception_filter(PEXCEPTION_POINTERS exception_pointers);
// Define the application name based on the target architecture:
#ifdef _WIN64
  #define DEFAULT_REG_VALUE 0xDEADBEEFBADC0DED
#else
  #define DEFAULT_REG_VALUE 0xDEADBEEF
#endif

// Some default settings:
#define DEFAULT_PROTECT (PAGE_EXECUTE_READWRITE)            // By default allocate RWE memory
#define DEFAULT_ALLOCATION_TYPE (MEM_RESERVE | MEM_COMMIT)  // By default reserve and commit memory on allocation.
#define STDIN_CHUNK_SIZE (0x1000)                           // Use a 0x1000 byte buffer to read data from stdin.

// get_value_or_offset converts a hexadicimal value in a string to a 32/64-bit integer value. The string can start
// with '$' to specify that the value is an offset from "memory base address". The converted integer value is stored
// in the VALUE variable specified by a pointer in the arguments. The end of the hexadecimal value in the string
// is stored in a char* also specified by a pointer in the arguments. The function returns true if the value is an
// offset from "memory base address" and false if it is not.
// This function is used to parse values specified on the command line.
BOOL get_value_or_offset(char *start_of_value, char **end_of_value, VALUE *pvalue) {
  BOOL is_offset;
  is_offset = (start_of_value[0] == '$');
  if (is_offset) start_of_value += 1;
  if (start_of_value[0] == '-') {
    *pvalue = 0 - STR_TO_VAL(start_of_value + 1, end_of_value, 16);
  } else {
    *pvalue = STR_TO_VAL(start_of_value, end_of_value, 16);
  }
  return is_offset;
}
// User can supply files to be loaded or values to be set at specific locations in memory using the command line.
// For each such command-line setting, a "data chunk" is created that represents this setting. These data chunks
// are stored in a linked list. Each data chunk has information about the data to store and where to store it:
struct data_chunk {
  VALUE address;                        // Address or offset where to store the data
  BOOL address_is_offset;               // Is address an offset from "memory base address"?
  char* pdata;                          // Pointer to the data to store.
  unsigned int size;                    // Number of bytes of data.
  BOOL data_is_value;                   // Is the data a 32/64-bit value?
  BOOL data_is_offset;                  // Is the data a 32/64-bit offset from "memory base address"?
  struct data_chunk *pnext_chunk;       // Pointer to next data chunk in linked list or NULL for end of list.
};
// add_data_chunk is used to add a "data chunk" to a linked list of chunks. A pointer to the first chunk in the
// linked list is specified by a pointer in the arguments. If the list is empty, the pointer to the first chunk
// must be NULL. In this case, a new list is created by setting this pointer to the new data chunk.
void add_data_chunk(struct data_chunk **ppfirst_data_chunk, struct data_chunk *pdata_chunk) {
  if (*ppfirst_data_chunk == NULL) {
    // The list is empty, set the "first data chunk pointer" to point to the new chunk, thereby creating a new
    // linked list with the new chunk as the first and only entry:
    *ppfirst_data_chunk = pdata_chunk;
  } else {
    // Walk the linked list to find the last chunk, which has the "pointer to the next chunk" set to NULL:
    struct data_chunk *pdata_chunk_in_chain = *ppfirst_data_chunk;
    while (pdata_chunk_in_chain->pnext_chunk != NULL) {
      pdata_chunk_in_chain = pdata_chunk_in_chain->pnext_chunk;
    }
    // Add the new chunk to the linked list by setting the "pointer to the next chunk" of the last chunk in the
    // linked list to point to the new chunk:
    pdata_chunk_in_chain->pnext_chunk = pdata_chunk;
  }
}
// add_value_as_data_chunk creates a data chunk to store a 32/64-bit value or offset at the given address or offset.
// The address or offset at which to store the value is specified in the arguments as well as if this is an address
// or an offset. The 32/64-bit value or offset must be parsed from a string specified in the arguments. The new data
// chunk is added to a linked list specified by a pointer in the arguments. The function returns a char* that points
// to the end of the hexadecimal value in the value string supplied in the arguments.
char* add_value_as_data_chunk(struct data_chunk **ppfirst_data_chunk, VALUE address, BOOL address_is_offset, 
    char* value_string) {
  struct data_chunk *pdata_chunk;
  VALUE *pvalue;
  char *end_of_value;
  // Allocate one block of memory to hold the data chunk and the value:
  char *pchunk_and_data = malloc(sizeof(struct data_chunk) + sizeof(VALUE));
  if (pchunk_and_data == 0) {
    perror("Memory cannot be allocated for data chunk.");
    exit(1);
  }
  // The data chunk will be stored at the start of the allocated memory:
  pdata_chunk = (struct data_chunk *) pchunk_and_data;
  // The value will be stored at the end of the allocated memory:
  pvalue = (VALUE*) (pchunk_and_data + sizeof(struct data_chunk));
  // Populate the data chunk:
  pdata_chunk->address = address;
  pdata_chunk->address_is_offset = address_is_offset;
  pdata_chunk->pdata = (char*) pvalue;
  // This data chunk is either a value or an offset, but not both:
  pdata_chunk->data_is_offset = get_value_or_offset(value_string, &end_of_value, pvalue);
  pdata_chunk->data_is_value = !pdata_chunk->data_is_offset;
  pdata_chunk->size = sizeof(VALUE);
  pdata_chunk->pnext_chunk = NULL;
  // Add the data chunk to the linked list:
  add_data_chunk(ppfirst_data_chunk, pdata_chunk);
  return end_of_value;
}

// add_file_as_data_chunk creates a data chunk to store data read from a file or stdin at the given address or
// offset. The address or offset at which to store the value is specified in the arguments as well as if this is an
// address or an offset. The name of file to be read is specified in the arguments, if this is "con", data will be
// read from stdin. The data can be converted to unicode by inserting a NULL after each byte. The new data chunk is
// added to a linked list specified by a pointer in the arguments.
void add_file_as_data_chunk(struct data_chunk **ppfirst_data_chunk, VALUE address, BOOL address_is_offset, 
    BOOL unicode, char* file_name) {
  struct data_chunk *pdata_chunk = NULL;
  char *pdata = NULL;
  HANDLE file = INVALID_HANDLE_VALUE;
  // file_size keeps track of the number of bytes read, data_size keeps track of the number of bytes needed to store
  // the data. The later may be twice as large as the former when the data needs to be converted to unicode. 
  // bytes_read is used to track how many bytes have been read from stdin or a file:
  DWORD file_size = 0, data_size = 0, bytes_read = 0;
  char* pchunk_and_data = NULL;
  // Read from stddin if filename is "con", otherwise read from the file:
  if (stricmp(file_name, "con") == 0) {
    // Find out where stdin is:
    file = GetStdHandle(STD_INPUT_HANDLE);
    if (file == INVALID_HANDLE_VALUE) {
      perror("Stdin cannot be opened.");
      exit(1);
    }
    do {
      // data_size is used for the buffer size, add a chunk's size to make room to read data, taking into account
      // that conversion to unicode doubles the size of the data:
      if (unicode) data_size += 2 * STDIN_CHUNK_SIZE;
      else data_size += STDIN_CHUNK_SIZE;
      // Is this the first time we're reading data?
      if (bytes_read == 0) {
        // Yes: allocate one block of memory to hold the data chunk and the buffer:
        pchunk_and_data = malloc(sizeof(struct data_chunk) + data_size);
        if (pchunk_and_data == 0) {
          perror("Memory cannot be allocated for stdin data chunk.");
          exit(1);
        }
      } else {
        // No: reallocate one larger block of memory to hold the data chunk and the buffer:
        pchunk_and_data = realloc(pchunk_and_data, data_size);
        if (pchunk_and_data == 0) {
          perror("Additional memory cannot be allocated for stdin data chunk.");
          exit(1);
        }
      }
      // The data chunk will be stored at the start of the allocated memory:
      pdata_chunk = (struct data_chunk *) pchunk_and_data;
      // The data will be stored after the data chunk:
      pdata = (char*) (pchunk_and_data + sizeof(struct data_chunk));
      // Read a chunk of data from stdin:
      if (ReadFile(file, pdata + file_size, STDIN_CHUNK_SIZE, &bytes_read, NULL) == FALSE) {
        perror("File cannot be read!");
        exit(1);
      }
      // Count the number of bytes read:
      file_size += bytes_read;
    } while (bytes_read == STDIN_CHUNK_SIZE);
    // If less than a complete chunk of data was read, data_size is now too large. The followin will fix this, while
    // taking into account that conversion to unicode doubles the size of the data:
    if (unicode) data_size += 2 * bytes_read - 2 * STDIN_CHUNK_SIZE;
    else data_size += bytes_read - STDIN_CHUNK_SIZE;
  } else {
    // Open the file:
    file = CreateFile(file_name, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
      fprintf(stderr, "Cannot open file \"%s\".\r\n", file_name);
      exit(1);
    }
    // Get the size of the file:
    file_size = GetFileSize(file, NULL);
    if (file_size == INVALID_FILE_SIZE) {
      perror("Size of file cannot be retreived.");
      exit(1);
    }
    // Allocate one block of memory to hold the data chunk and the data read from the file, taking into account
    // that conversion to unicode doubles the size of the data:
    data_size = file_size;
    if (unicode) data_size *= 2;
    pchunk_and_data = malloc(sizeof(struct data_chunk) + data_size);
    if (pchunk_and_data == 0) {
      perror("Memory cannot be allocate for file data chunk.");
      exit(1);
    }
    // The data chunk will be stored at the start of the allocated memory:
    pdata_chunk = (struct data_chunk *) pchunk_and_data;
    // The data will be stored after the data chunk:
    pdata = (char*) (pchunk_and_data + sizeof(struct data_chunk));
    // Read the data from the file:
    if (ReadFile(file, pdata, file_size, &bytes_read, NULL) == FALSE) {
      perror("File cannot be read!");
      exit(1);
    }
    if (bytes_read < file_size) {
      fprintf(stderr, "Only %d of %d bytes of data can be read from \"%s\"", bytes_read, file_size, file_name);
      exit(1);
    }
  }
  // Convert data to Unicode if needed:
  if (unicode) {
    int i;
    for (i = file_size - 1; i >= 0; i--) {
      ((WORD*)pdata)[i] = (WORD)(pdata[i]);
    }
  }
  // Populate the data chunk:
  pdata_chunk->address = address;
  pdata_chunk->address_is_offset = address_is_offset;
  pdata_chunk->pdata = (char*) pdata;
  pdata_chunk->data_is_value = FALSE;
  pdata_chunk->data_is_offset = FALSE;
  pdata_chunk->size = data_size;
  pdata_chunk->pnext_chunk = NULL;
  // Add the data chunk to the linked list:
  add_data_chunk(ppfirst_data_chunk, pdata_chunk);
}

// This is a bit of a wild hack to display two formatted strings, the first padded to 28 chars. This way, there is
// no need to use a buffer and snprintf: the first "argument" is printed, then spaces are printed to pad to 28 chars
// and finally the second "argument" is printed. (Both "arguments" are in fact sets of arguments to be passed to
// printf).
#define PRINT_STATUS(header_arguments, footer_arguments) ( \
  _print_padding(28 - (printf header_arguments)), (printf footer_arguments) \
)
void _print_padding(int padding) {
  while (padding > 0) printf(" "), padding--;
}
// Output some information that helps the user understand this application:
void help(void) {
  printf("Test shellcodes and ret-into-libc data.\r\n");
  printf("\r\n");
  printf("usage: " QUOTE(BUILD_PROJECT) " [set register] [set memory] [options...]\r\n");
  printf("or:    " QUOTE(BUILD_PROJECT) " --loadlibrary \"module file name\"\r\n");
  printf("\r\n");
  printf(QUOTE(BUILD_PROJECT) " can be used to test shellcode and ret-into-libc stacks or\r\n");
  printf("to load a dll into the process by calling kernel32!LoadLibrary. The later is\r\n");
  printf("useful when testing a dll that executes shellcode when it gets loaded.\r\n");
  printf("The former allocates memory at any valid address, of any valid size,\r\n");
  printf("protection flags and allocation type. It set registers to any values and can\r\n");
  printf("set bytes at any location in memory to any value. It can load binary files\r\n");
  printf("(shellcode or ret-into-libc stacks) at any location in memory.\r\n");
  printf("It can fake a ret-into-libc, an overwritten return address or a JMP to any\r\n");
  printf("address and trigger a debugger break before doing so, to attach your debugger\r\n.");
  printf("Exceptions can be handled to output information about them to stderr.\r\n");
  printf("\r\n");
  printf("Registers can be using \"{reg}={value}\", where {reg} is the name of a register\r\n");
  printf("and {value} is a %d-bit hexadecimal value or an offset*.\r\n", VALUE_BITS);
  printf("Memory can be set using \"[{address}]={data}\", where {address} is the address\r\n");
  printf("or offset* at which to store the data, and {data} can be on of the following:\r\n");
  printf("  value:{value} to write a %d-bit hexadecimal number or offset* to the address.\r\n", VALUE_BITS);
  printf("  ascii:{file name} to read the specified file into memory at the given address.\r\n");
  printf("  uncode:{file name} to read the specified file, insert a NULL byte after every\r\n");
  printf("  byte of the file and store the result in memory at the given address.\r\n");
  printf("  (Use \"con\" as the file name to read data from stdin).\r\n");
  printf("\r\n");
  printf("* values and addresses can be entered as a hexadecimal number or as an offset\r\n");
  printf("from the base address of the allocated memory. To specify an offset use one of\r\n");
  printf("the following: $, $+{value} or $-{value}.\r\n");
  printf("\r\n");
  printf("Options\r\n");
  printf("    --loadlibrary \"module file name\"\r\n");
  printf("                     Attempt to load the given module into the process and\r\n");
  printf("                     then terminate the application.\r\n");
  printf("Non \"LoadLibrary\" options:\r\n");
  printf("    --mem:address    Specify the address at which to allocate memory.\r\n");
  printf("    --mem:size       Specify the number of bytes of memory to allocate.\r\n");
  printf("    --mem:type       Specify the \"flAllocationType\" argument to be passed to\r\n");
  printf("                     VirtualAlloc - see MSDN for more details.\r\n");
  printf("    --mem:protect    Specify the \"flProtect\" argument to be passed to\r\n");
  printf("                     VirtualAlloc - see MSDN for more details.\r\n");
  printf("    --ret            Use a RET instruction to set EIP/RIP, instead of the\r\n");
  printf("                     default JMP instruction.\r\n");
  printf("General options:\r\n");
  printf("    --verbose        Output verbose information.\r\n");
  printf("    --delay:time     Wait the given number of milliseconds before executing the\r\n");
  printf("                     shellcode or loading the library.\r\n");
  printf("    --int3           Trigger a debugger breakpoint before setting EIP/RIP or.\r\n");
  printf("                     loading the module into the process.\r\n");
  printf("    --EH             Use a Structured Exception Handler filter to catch all\r\n");
  printf("                     unhandled exceptions and report exception information\r\n");
  printf("                     before terminating the application.\r\n");
  printf("    --EH --EH        Same as \"--EH\" but add a Vectored Exception Handler to\r\n");
  printf("                     catch first change exceptions and report exception\r\n");
  printf("                     information about them as well.\r\n");
  printf("  (Debug breakpoints are ignored by both --EH settings; no information is\r\n");
  printf("  reported and the application is not terminated).\r\n");
  printf("Stand-alone options:\r\n");
  printf("    --help           Output this information.\r\n");
  printf("    --version        Output version and build information.\r\n");
  printf("\r\n");
  printf("Example usage\r\n");
  printf("  " QUOTE(BUILD_PROJECT) " eip=$ [$]=ascii:w%d-writeconsole-shellcode.bin\r\n", VALUE_BITS);
  printf("  " QUOTE(BUILD_PROJECT) " --loadlibrary w%d-writeconsole-shellcode.dll\r\n", VALUE_BITS);
}
// Output some information about the version and build of this application
void version(void) {
  printf(QUOTE(BUILD_PROJECT) " version " QUOTE(BUILD_VERSION) ", build #" QUOTE(BUILD_NUMBER) 
      " created on " QUOTE(BUILD_TIMESTAMP) "\r\n");
  printf("Copyright (C) 2006-2009 by SkyLined <berendjanwever@gmail.com>\r\n");
}

int main(int argc, char** argv) {
  int i, j;
  // A structure that contains information about what value to set a register to.
  struct register_setting {
    char* name;                           // The name of the register,
    VALUE value;                          // The value or offset to set the register to,
    BOOL is_offset;                       // Should the register be set to "memory base address" + value?
    BOOL is_set;                          // Was this register explicitly set on the command-line?
  };
  #ifdef _WIN64
    struct register_setting register_settings[] = {
        {"rax", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"rcx", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"rdx", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"rbx", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"rsp", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"rbp", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"rsi", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"rdi", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"r8",  DEFAULT_REG_VALUE, FALSE, FALSE},
        {"r9",  DEFAULT_REG_VALUE, FALSE, FALSE},
        {"r10", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"r11", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"r12", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"r13", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"r14", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"r15", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"rip", DEFAULT_REG_VALUE, FALSE, FALSE}
    };
    #define register_settings_count (sizeof(register_settings) / sizeof(struct register_setting))
    #define register_setting_sp (register_settings[0x04])
    #define register_setting_ip (register_settings[0x10])
    VALUE register_values[0x11] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    #define register_value_sp (register_values[0x04])
    #define register_value_ip (register_values[0x10])
  #else
    struct register_setting register_settings[] = {
        {"eax", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"ecx", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"edx", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"ebx", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"esp", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"ebp", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"esi", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"edi", DEFAULT_REG_VALUE, FALSE, FALSE},
        {"eip", DEFAULT_REG_VALUE, FALSE, FALSE}
    };
    #define register_settings_count (sizeof(register_settings) / sizeof(struct register_setting))
    #define register_setting_sp (register_settings[0x04])
    #define register_setting_ip (register_settings[0x08])
    VALUE register_values[0x9] = {0,0,0,0,0,0,0,0,0};
    #define register_value_sp (register_values[0x04])
    #define register_value_ip (register_values[0x08])
  #endif

  struct data_chunk *pfirst_data_chunk = NULL, *pdata_chunk;

  SYSTEM_INFO system_info;
  BOOL memory_size_set = FALSE;
  size_t memory_size = 0;
  BOOL memory_base_address_set = FALSE;
  VALUE memory_base_address = 0, memory_address;
  int allocation_type = DEFAULT_ALLOCATION_TYPE, protect = DEFAULT_PROTECT, delay = 0;
  BOOL switch_verbose = 0, switch_int3 = 0, switch_EH = 0, switch_ret = 0, switch_loadlibrary = 0;
  char *module_file_name = NULL;
  HMODULE module = NULL;
  PVOID VEH = NULL;

  if (argc == 1 || (argc == 2 && stricmp(argv[1], "--help") == 0)) {
    help();
    exit(0);
  }
  if (argc == 2 && stricmp(argv[1], "--version") == 0) {
    version();
    exit(0);
  }

  // Parse arguments
  for (i = 1; i < argc; i++) {
    if (strnicmp(argv[i], "--mem:address=", 14) == 0) {
      memory_base_address = STR_TO_VAL(argv[i] + 14, NULL, 16);
      memory_base_address_set = TRUE;
    } else if (strnicmp(argv[i], "--mem:size=", 11) == 0) {
      memory_size = (size_t) strtol(argv[i] + 11, NULL, 16);
      memory_size_set = TRUE;
    } else if (strnicmp(argv[i], "--mem:type=", 11) == 0) {
      allocation_type = (int) strtol(argv[i] + 11, NULL, 16);
    } else if (strnicmp(argv[i], "--mem:protect=", 14) == 0) {
      protect = (int) strtol(argv[i] + 14, NULL, 16);
    } else if (strnicmp(argv[i], "--delay=", 8) == 0) {
      delay = (int) strtol(argv[i] + 8, NULL, 16);
    } else if (stricmp(argv[i], "--verbose") == 0) {
      switch_verbose++;
    } else if (stricmp(argv[i], "--int3") == 0) {
      switch_int3++;
    } else if (stricmp(argv[i], "--EH") == 0) {
      switch_EH++;
    } else if (stricmp(argv[i], "--ret") == 0) {
      switch_ret++;
    } else if (stricmp(argv[i], "--loadlibrary") == 0) {
      switch_loadlibrary++;
      if (i+1 == argc) {
        printf("The \"--loadlibrary\" option requires a module file name as the next argument.\r\n");
        exit(1);
      }
      module_file_name = argv[++i];
    } else if (stricmp(argv[i], "--help") == 0 || stricmp(argv[i], "--version") == 0) {
      printf("The \"--help\" and \"--version\" options cannot be used in combination with\r\n");
      printf("any other options.\r\n");
      exit(1);
    } else if (strncmp(argv[i], "--", 2) == 0) {
      printf("Illegal flag \"%s\".\r\n", argv[i]);
      printf("Try \"w%d-testival.exe --help\"\r\n", VALUE_BITS);
      exit(1);
    } else if (argv[i][0] == '[') {
      VALUE address;
      BOOL address_is_offset;
      char *start_of_address, *end_of_address;
      start_of_address = argv[i] + 1;
      address_is_offset = get_value_or_offset(start_of_address, &end_of_address, &address);
      if (strncmp(end_of_address, "]=", 2) != 0) {
        printf("Illegal data chunk argument \"%s\".\r\n", argv[i]);
        exit(1);
      }
      if (strnicmp(end_of_address + 2, "value:", 6) == 0) {
        end_of_address = add_value_as_data_chunk(&pfirst_data_chunk, address, address_is_offset, end_of_address + 8);
        // Check end_of_address == argv[i] + strlen(argv[i]
      } else if (strnicmp(end_of_address + 2, "ascii:", 6) == 0) {
        add_file_as_data_chunk(&pfirst_data_chunk, address, address_is_offset, FALSE, end_of_address + 8);
      } else if (strnicmp(end_of_address + 2, "unicode:", 8) == 0) {
        add_file_as_data_chunk(&pfirst_data_chunk, address, address_is_offset, TRUE, end_of_address + 10);
      } else {
        printf("Illegal data chunk argument \"%s\".\r\n", argv[i]);
        exit(1);
      }
    } else {
      for (j = 0; j < register_settings_count; j++) {
        size_t reg_name_length;
        if (register_settings[j].name == NULL) continue; // Ignore "unnamed" registers
        reg_name_length = strlen(register_settings[j].name); // Cache length
        if (
            strlen(argv[i]) > reg_name_length + 1 && // at least "reg_name=X"
            strnicmp(argv[i], register_settings[j].name, reg_name_length) == 0 &&
            argv[i][strlen(register_settings[j].name)] == '='
        ) {
          char *value_end;
          char *value_start = argv[i] + reg_name_length + 1;
          register_settings[j].is_offset = get_value_or_offset(value_start, &value_end, &(register_settings[j].value));
          register_settings[j].is_set = TRUE;
          break;
        }
      }
      if (j == register_settings_count) {
        printf("Illegal argument: \"%s\".\r\n", argv[i]);
        exit(1);
      }
    }
  }
  // There are two things this program can do: test shellcode/ret-into-libc stacks or load a library:
  if (switch_loadlibrary == 0) {
    // Check that RSP or return address is set and warn about problems with setting ESP.
    if (!register_setting_sp.is_set) {
      if (!register_setting_ip.is_set) {
        printf("Either the \"%s\" or \"%s\" register must be set.\r\n"
            "(Otherwise random memory would get executed, which isn't very useful).\r\n",
            register_setting_sp.name, register_setting_ip.name);
        exit(1);
      } else if (switch_verbose) {
        printf("Warning: changing \"%s\" may prevent JIT debuggers from attaching to the process\r\n"
            "  in case of an exception.\r\n", register_setting_sp.name);
        if (switch_EH) {
          printf("  Also, the EH handler that reports information about exceptions is more\r\n"
              "  likely to fail because of secondary exceptions.\r\n");
        }
      }
    }
    // Allocate memory
    if (!memory_size_set) {
      GetSystemInfo(&system_info);
      memory_size = (size_t)system_info.dwPageSize;
      memory_size_set = TRUE;
    }
    if (switch_verbose) {
      printf("Memory allocation:\r\n");
      PRINT_STATUS(("  Size"), ("= %X bytes.\r\n", memory_size));
      if (allocation_type != DEFAULT_ALLOCATION_TYPE) {
        PRINT_STATUS(("  Allocation type"), ("= %X.\r\n", allocation_type));
      }
      if (memory_base_address_set) {
        PRINT_STATUS(("  Requested address"), ("= " FMT_VAL ".\r\n", memory_base_address));
      }
    }
    memory_address = (VALUE)VirtualAlloc((LPVOID)memory_base_address, memory_size, allocation_type, DEFAULT_PROTECT);
    if (memory_address == 0) {
      perror("Memory cannot be allocated!");
      exit(1);
    }
    if (!memory_base_address_set) memory_base_address = memory_address;
    if (switch_verbose) {
      PRINT_STATUS(("  Actual address"), ("= " FMT_VAL ".\r\n", memory_address));
    // Apply data chunks
      printf("Data, registers and return address:\r\n");
    }
    pdata_chunk = pfirst_data_chunk;
    while (pdata_chunk != NULL) {
      VALUE address = pdata_chunk->address;
      if (pdata_chunk->address_is_offset) {
        address += (VALUE)memory_base_address;
      }
      if (pdata_chunk->data_is_value || pdata_chunk->data_is_offset) {
        VALUE value = *(VALUE*)pdata_chunk->pdata;
        if (pdata_chunk->data_is_offset) {
          VALUE offset = value;
          value += (VALUE)memory_base_address;
          if (switch_verbose) {
            if (offset == 0) {
              PRINT_STATUS(("  [" FMT_VAL "]", address), ("= " FMT_VAL " ($, default)\r\n", value));
            } else if (offset > VALUE_MAX_SIGNED) {
              PRINT_STATUS(("  [" FMT_VAL "]", address), ("= " FMT_VAL " ($-%X, default)\r\n", value, 0-offset));
            } else {
              PRINT_STATUS(("  [" FMT_VAL "]", address), ("= " FMT_VAL " ($+%X, default)\r\n", value, offset));
            }
          }
        } else {
          if (switch_verbose) PRINT_STATUS(("  [" FMT_VAL "]", address), ("= " FMT_VAL "\r\n", value));
        }
        *(VALUE*)address = value;
      } else {
        if (switch_verbose) PRINT_STATUS(("  [" FMT_VAL "]", address), ("= %X bytes of data.\r\n", pdata_chunk->size));
        memcpy((char*) address, pdata_chunk->pdata, pdata_chunk->size);
      }
      pdata_chunk = pdata_chunk->pnext_chunk;
    }
    // Apply offsets in registers and create struct registers
    for (i = 0; i < register_settings_count; i++) {
      VALUE value = register_settings[i].value;
      VALUE offset = 0;
      if (register_settings[i].is_offset) {
        offset = value;
        value += (VALUE)memory_base_address;
      }
      if (switch_verbose) {
        if (!register_settings[i].is_set) {
          if (&(register_settings[i]) == &(register_setting_sp)) {
            PRINT_STATUS(("  %-18s", register_settings[i].name), ("= ??? (unmodified)\r\n"));
          } else if (register_settings[i].is_offset) {
            if (offset == 0) {
              PRINT_STATUS(("  %-18s", register_settings[i].name), ("= " FMT_VAL " ($, default)\r\n", value));
            } else if (offset > 0x7FFFFFFF) {
              PRINT_STATUS(("  %-18s", register_settings[i].name), ("= " FMT_VAL " ($-%X, default)\r\n", value, 0-offset));
            } else {
              PRINT_STATUS(("  %-18s", register_settings[i].name), ("= " FMT_VAL " ($+%X, default)\r\n", value, offset));
            }
          } else {
            PRINT_STATUS(("  %-18s", register_settings[i].name), ("= " FMT_VAL " (default)\r\n", value));
          }
        } else if (register_settings[i].is_offset) {
            if (offset == 0) {
              PRINT_STATUS(("  %-18s", register_settings[i].name), ("= " FMT_VAL " ($)\r\n", value));
            } else if (offset > 0x7FFFFFFF) {
              PRINT_STATUS(("  %-18s", register_settings[i].name), ("= " FMT_VAL " ($-%X)\r\n", value, 0-offset));
            } else {
              PRINT_STATUS(("  %-18s", register_settings[i].name), ("= " FMT_VAL " ($+%X)\r\n", value, offset));
            }
        } else {
          PRINT_STATUS(("  %-18s", register_settings[i].name), ("= " FMT_VAL "\r\n", value));
        }
      }
      register_values[i] = value;
    }
    // Set up environment
    if (protect != DEFAULT_PROTECT) {
      DWORD saved_protect;
      if (switch_verbose) printf("Adjusting memory protection:\r\n");
      if (VirtualProtect((LPVOID)memory_address, 1, protect, &saved_protect) == 0) {
        perror("Memory protection cannot be changed!");
        exit(1);
      }
      if (switch_verbose) PRINT_STATUS(("  Memory protection"), ("= %X.\r\n", protect));
    }
    // Execute the shellcode
    if (switch_verbose) {
      char* int3_message = "";
      if (switch_int3) {
        int3_message = " after triggering an int3";
      }
      if (register_setting_ip.is_set) {
        if (switch_ret) {
          printf("Executing shellcode%s by returning to " FMT_VAL ".\r\n", int3_message, register_value_ip);
        } else if (register_setting_ip.is_set) {
          printf("Executing shellcode%s by jumping to " FMT_VAL ".\r\n", int3_message, register_value_ip);
        }
      } else if (register_setting_sp.is_set) {
        printf("Executing ret-into-libc%s with stack at " FMT_VAL ".\r\n", int3_message, register_value_sp);
      } else {
        printf("Cannot ret-into-libc without setting ESP.\r\n");
        exit(1);
      }
    }
    if (switch_EH) {
      SetUnhandledExceptionFilter(unhandled_exception_filter);
      if (switch_EH > 1) {
        VEH = AddVectoredExceptionHandler(1, vectored_exception_handler);
        if (VEH == NULL) {
          perror("Cannot register vectored exception handler.\r\n");
          exit(1);
        }
      }
    }
    Sleep(delay);
    asm_SetRegisters(register_values, switch_int3 > 0, switch_ret > 0, register_setting_sp.is_set, register_setting_ip.is_set);
    if (switch_EH > 1 && RemoveVectoredExceptionHandler(VEH) == 0) {
      perror("Cannot unregister vectored exception handler.\r\n");
      exit(1);
    }
  } else { // switch_loadlibrary > 0
    if (switch_verbose) {
      char* int3_message = "";
      if (switch_int3) {
        int3_message = " after triggering an int3";
      }
      printf("Loading module \"%s\"%s...\r\n", module_file_name, int3_message);
    }
    if (switch_EH) {
      SetUnhandledExceptionFilter(unhandled_exception_filter);
      if (switch_EH > 1) {
        VEH = AddVectoredExceptionHandler(1, vectored_exception_handler);
        if (VEH == NULL) {
          perror("Cannot register vectored exception handler.\r\n");
          exit(1);
        }
      }
    }
    Sleep(delay);
    if (switch_int3) __debugbreak();
    module = LoadLibrary(module_file_name);
    if (switch_EH > 1 && RemoveVectoredExceptionHandler(VEH) == 0) {
      perror("Cannot unregister vectored exception handler.\r\n");
      exit(1);
    }
    if (module == NULL) {
      fprintf(stderr, "Failed to load module \"%s\".\r\n", module_file_name);
      exit(1);
    } else {
      if (switch_verbose) printf("Module \"%s\" successfully loaded.", module_file_name);
    }
  }
  exit(0);
}