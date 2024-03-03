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
CMAKE_SOURCE_DIR = /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild

# Utility rule file for zstd-populate.

# Include any custom commands dependencies for this target.
include CMakeFiles/zstd-populate.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/zstd-populate.dir/progress.make

CMakeFiles/zstd-populate: CMakeFiles/zstd-populate-complete

CMakeFiles/zstd-populate-complete: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-install
CMakeFiles/zstd-populate-complete: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-mkdir
CMakeFiles/zstd-populate-complete: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-download
CMakeFiles/zstd-populate-complete: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-update
CMakeFiles/zstd-populate-complete: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-patch
CMakeFiles/zstd-populate-complete: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-configure
CMakeFiles/zstd-populate-complete: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-build
CMakeFiles/zstd-populate-complete: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-install
CMakeFiles/zstd-populate-complete: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-test
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Completed 'zstd-populate'"
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles
	/usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles/zstd-populate-complete
	/usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-done

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-update:
.PHONY : zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-update

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-build: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-configure
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "No build step for 'zstd-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && /usr/local/bin/cmake -E echo_append
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-build

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-configure: zstd-populate-prefix/tmp/zstd-populate-cfgcmd.txt
zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-configure: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-patch
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "No configure step for 'zstd-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && /usr/local/bin/cmake -E echo_append
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-configure

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-download: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-gitinfo.txt
zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-download: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-mkdir
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Performing download step (git clone) for 'zstd-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty && /usr/local/bin/cmake -P /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/tmp/zstd-populate-gitclone.cmake
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-download

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-install: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-build
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "No install step for 'zstd-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && /usr/local/bin/cmake -E echo_append
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-install

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-mkdir:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Creating directories for 'zstd-populate'"
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-src
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/tmp
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp
	/usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-mkdir

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-patch: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-update
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "No patch step for 'zstd-populate'"
	/usr/local/bin/cmake -E echo_append
	/usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-patch

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-update:
.PHONY : zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-update

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-test: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-install
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "No test step for 'zstd-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && /usr/local/bin/cmake -E echo_append
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-build && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-test

zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-update: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-download
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Performing update step for 'zstd-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-src && /usr/local/bin/cmake -P /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/zstd-populate-prefix/tmp/zstd-populate-gitupdate.cmake

zstd-populate: CMakeFiles/zstd-populate
zstd-populate: CMakeFiles/zstd-populate-complete
zstd-populate: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-build
zstd-populate: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-configure
zstd-populate: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-download
zstd-populate: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-install
zstd-populate: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-mkdir
zstd-populate: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-patch
zstd-populate: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-test
zstd-populate: zstd-populate-prefix/src/zstd-populate-stamp/zstd-populate-update
zstd-populate: CMakeFiles/zstd-populate.dir/build.make
.PHONY : zstd-populate

# Rule to build all files generated by this target.
CMakeFiles/zstd-populate.dir/build: zstd-populate
.PHONY : CMakeFiles/zstd-populate.dir/build

CMakeFiles/zstd-populate.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/zstd-populate.dir/cmake_clean.cmake
.PHONY : CMakeFiles/zstd-populate.dir/clean

CMakeFiles/zstd-populate.dir/depend:
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zstd-subbuild/CMakeFiles/zstd-populate.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/zstd-populate.dir/depend
