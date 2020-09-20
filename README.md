# jedec2bin
Utility to generate equations from a JEDEC file of an GAL16V8 

Note: this tool is not thoroughly developed, but it should produce valid equations for simple JEDEC files.
GAL16V8 is only supported at the time.

# Build and usage
Requires a C++11 GNU compiler.
To build:
```
mkdir _builds && cd _builds
cmake ..
make -j$(nproc)
```

Usage:
```
# from within _build
./src/jedec2bin path_to_your_jedec_file.jed
```

Note: there's a sample .jed file provided on the `src` directory that will be used when debugging inside vscode.