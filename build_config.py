build_config = {
  "version": "1.0",
  "debug": True,
  "projects": {
    "w32-testival": {
      "architecture": "x86",
      "files": {
        "build\\exe\\w32-testival.exe": {
          "sources": ["build\\w32-main.obj", "build\\win32-exception-handling.obj", "build\\w32-asm-setregisters.obj"],
        },
        "build\\w32-main.obj": {
          "sources": ["main.cpp"]
        },
        "build\\win32-exception-handling.obj": {
          "sources": ["exception-handling.cpp"]
        },
        "build\\w32-asm-setregisters.obj": {
          "sources": ["w32-asm-setregisters.asm"],
        }
      },
      "test commands": ["test-w32-testival.cmd"]
    },
    "w64-testival": {
      "architecture": "x64",
      "files": {
        "build\\exe\\w64-testival.exe": {
          "sources": ["build\\w64-main.obj", "build\\win64-exception-handling.obj", "build\\w64-asm-setregisters.obj"]
        },
        "build\\w64-main.obj": {
          "sources": ["main.cpp"]
        },
        "build\\win64-exception-handling.obj": {
          "sources": ["exception-handling.cpp"]
        },
        "build\\w64-asm-setregisters.obj": {
          "sources": ["w64-asm-setregisters.asm"]
        }
      },
      "test commands": ["test-w64-testival.cmd"]
    }
  }
}