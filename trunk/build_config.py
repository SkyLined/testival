build_config = {
  "version": "1.0",
  "folders": ["writeconsole-shellcodes"],
  "debug": True,
  "projects": {
    "w32-testival": {
      "architecture": "x86",
      "files": {
        "w32-testival.exe": {
          "sources": ["w32-main.obj", "win32-exception-handling.obj", "w32-asm-setregisters.obj"],
        },
        "w32-main.obj": {
          "sources": ["main.c"]
        },
        "win32-exception-handling.obj": {
          "sources": ["exception-handling.c"]
        },
        "w32-asm-setregisters.obj": {
          "sources": ["w32-asm-setregisters.asm"],
        }
      },
      "test commands": ["test-w32-testival.cmd"]
    },
    "w64-testival": {
      "architecture": "x64",
      "files": {
        "w64-testival.exe": {
          "sources": ["w64-main.obj", "win64-exception-handling.obj", "w64-asm-setregisters.obj"]
        },
        "w64-main.obj": {
          "sources": ["main.c"]
        },
        "win64-exception-handling.obj": {
          "sources": ["exception-handling.c"]
        },
        "w64-asm-setregisters.obj": {
          "sources": ["w64-asm-setregisters.asm"]
        }
      },
      "test commands": ["test-w64-testival.cmd"]
    }
  }
}