# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /nfshome/bjung022/Project/ShaftDB

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /nfshome/bjung022/Project/ShaftDB/build

# Utility rule file for clean-all.

# Include any custom commands dependencies for this target.
include thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/compiler_depend.make

# Include the progress variables for this target.
include thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/progress.make

thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all:
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && /usr/bin/make clean
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && rm -rf /nfshome/bjung022/Project/ShaftDB/build/

clean-all: thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all
clean-all: thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/build.make
.PHONY : clean-all

# Rule to build all files generated by this target.
thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/build: clean-all
.PHONY : thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/build

thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/clean:
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && $(CMAKE_COMMAND) -P CMakeFiles/clean-all.dir/cmake_clean.cmake
.PHONY : thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/clean

thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/depend:
	cd /nfshome/bjung022/Project/ShaftDB/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /nfshome/bjung022/Project/ShaftDB /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-src/build/cmake /nfshome/bjung022/Project/ShaftDB/build /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : thirdparty/SEAL/thirdparty/zstd-build/CMakeFiles/clean-all.dir/depend

