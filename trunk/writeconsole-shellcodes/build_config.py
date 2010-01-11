build_config = {
  "version": "0.1",
  "projects": {
    # Windows x86
    "w32-writeconsole-shellcode-hash-list.mac": {                               # List of hashes
      "files": {
        "w32-writeconsole-shellcode-hash-list.mac": {
          "sources": ["w32-writeconsole-shellcode-hash-list.txt"],
          "build commands": [
              ["hash\\hash.cmd",
                "--input=w32-writeconsole-shellcode-hash-list.txt",
                "--output=w32-writeconsole-shellcode-hash-list.mac"],
          ],
        },
      },
    },
    "w32-writeconsole-shellcode.bin": {                                         # Shellcode
      "architecture": "x86",
      "dependencies": ["w32-writeconsole-shellcode-hash-list.mac"],
      "files": {
        "w32-writeconsole-shellcode.bin": {
          "sources":  ["w32-writeconsole-shellcode.asm"],
          "includes": ["w32-writeconsole-shellcode-hash-list.mac"],
        },
      },
      "test commands": ["test-w32-writeconsole-shellcode.bin.cmd"],
    },
    "w32-writeconsole-shellcode-esp.bin": {                                     # Stack aligned shellcode
      "architecture": "x86",
      "dependencies": ["w32-writeconsole-shellcode-hash-list.mac"],
      "files": {
        "w32-writeconsole-shellcode-esp.bin": {
          "sources":  ["w32-writeconsole-shellcode.asm"],
          "includes": ["w32-writeconsole-shellcode-hash-list.mac"],
          "defines":  {"STACK_ALIGN": "TRUE"},
        }
      },
      "test commands": ["test-w32-writeconsole-shellcode-esp.bin.cmd"],
    },
    "w32-writeconsole-shellcode.dll": {                                         # DLL that executes the shellcode.
      "architecture": "x86",
      "dependencies": ["w32-writeconsole-shellcode.bin"],
      "files": {
        "w32-writeconsole-shellcode.dll": {
          "sources":  ["w32-writeconsole-shellcode.obj", "w32-dll-run-shellcode.obj"],
        },
        "w32-writeconsole-shellcode.obj": {
          "sources":  ["w32-writeconsole-shellcode.asm"],
          "includes": ["w64-writeconsole-shellcode-hash-list.mac"],
        },
        "w32-dll-run-shellcode.obj": {
          "sources": ["win-dll-run-shellcode.c"],
        }
      },
      "test commands": ["test-w32-writeconsole-shellcode.dll.cmd"]
    },
    # Windows x64
    "w64-writeconsole-shellcode-hash-list.mac": {                               # List of hashes
      "files": {
        "w64-writeconsole-shellcode-hash-list.mac": {
          "sources": ["w64-writeconsole-shellcode-hash-list.txt"],
          "build commands": [
              ["hash\\hash.cmd",
                "--input=w64-writeconsole-shellcode-hash-list.txt",
                "--output=w64-writeconsole-shellcode-hash-list.mac"],
          ],
        },
      },
    },
    "w64-writeconsole-shellcode.bin": {                                         # Shellcode
      "architecture": "x64",
      "dependencies": ["w64-writeconsole-shellcode-hash-list.mac"],
      "files": {
        "w64-writeconsole-shellcode.bin": {
          "sources":  ["w64-writeconsole-shellcode.asm"],
          "includes": ["w64-writeconsole-shellcode-hash-list.mac"],
        }
      },
      "test commands": ["test-w64-writeconsole-shellcode.bin.cmd"],
    },
    "w64-writeconsole-shellcode.dll": {                                         # DLL that executes the shellcode.
      "architecture": "x64",
      "dependencies": ["w64-writeconsole-shellcode.bin"],
      "files": {
        "w64-writeconsole-shellcode.dll": {
          "sources":  ["w64-writeconsole-shellcode.obj", "w64-dll-run-shellcode.obj"],
        },
        "w64-writeconsole-shellcode.obj": {
          "sources":  ["w64-writeconsole-shellcode.asm"],
          "includes": ["w64-writeconsole-shellcode-hash-list.mac"],
        },
        "w64-dll-run-shellcode.obj": {
          "sources":  ["win-dll-run-shellcode.c"],
        }
      },
      "test commands": ["test-w64-writeconsole-shellcode.dll.cmd"],
    },
    # Linux x86
    "l32-writeconsole-shellcode.bin": {
      "architecture": "x86",
      "files": {
        "l32-writeconsole-shellcode.bin": {
          "sources": ["l32-writeconsole-shellcode.asm"],
        }
      },
      "test commands": ["test-l32-writeconsole-shellcode.bin.cmd"],
    },
    "l32-writeconsole-shellcode-esp.bin": {
      "architecture": "x86",
      "files": {
        "l32-writeconsole-shellcode-esp.bin": {
          "sources": ["l32-writeconsole-shellcode.asm"],
          "defines": {"STACK_ALIGN": "TRUE"},
        }
      },
      "test commands": ["test-l32-writeconsole-shellcode-esp.bin.cmd"],
    }
  }
}
