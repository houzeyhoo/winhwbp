# WinHwBp
A hardware breakpoint management library for x86/x64 Windows. 

This is a revision of one of my older projects. Hopefully, somebody will find this useful.

## Usage
The library is designed to be simple and self-documenting. The [header file](include/winhwbp.h) contains documentation 
for the entire API surface. For a complete tutorial, see the [example program](example/main.c).

## Integration
The library uses CMake as its build system. You can integrate it with your project in two ways:

### Subdirectory
```cmake
add_subdirectory(deps/winhwbp)
target_link_libraries(your_project PRIVATE winhwbp::winhwbp)
```

### System Install
First, install the library system-wide:
```
cmake -B build
cmake --build build --config Release
cmake --install build
```
Then in your project:
```cmake
find_package(winhwbp CONFIG REQUIRED)
target_link_libraries(your_project PRIVATE winhwbp::winhwbp)
```
