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
CMAKE_SOURCE_DIR = /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild

# Utility rule file for zlib-populate.

# Include any custom commands dependencies for this target.
include CMakeFiles/zlib-populate.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/zlib-populate.dir/progress.make

CMakeFiles/zlib-populate: CMakeFiles/zlib-populate-complete

CMakeFiles/zlib-populate-complete: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-install
CMakeFiles/zlib-populate-complete: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-mkdir
CMakeFiles/zlib-populate-complete: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-download
CMakeFiles/zlib-populate-complete: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-update
CMakeFiles/zlib-populate-complete: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-patch
CMakeFiles/zlib-populate-complete: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-configure
CMakeFiles/zlib-populate-complete: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-build
CMakeFiles/zlib-populate-complete: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-install
CMakeFiles/zlib-populate-complete: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-test
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Completed 'zlib-populate'"
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles
	/usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles/zlib-populate-complete
	/usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-done

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-update:
.PHONY : zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-update

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-build: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-configure
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "No build step for 'zlib-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-build && /usr/local/bin/cmake -E echo_append
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-build && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-build

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-configure: zlib-populate-prefix/tmp/zlib-populate-cfgcmd.txt
zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-configure: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-patch
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "No configure step for 'zlib-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-build && /usr/local/bin/cmake -E echo_append
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-build && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-configure

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-download: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-gitinfo.txt
zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-download: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-mkdir
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Performing download step (git clone) for 'zlib-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty && /usr/local/bin/cmake -P /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/tmp/zlib-populate-gitclone.cmake
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-download

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-install: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-build
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "No install step for 'zlib-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-build && /usr/local/bin/cmake -E echo_append
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-build && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-install

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-mkdir:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Creating directories for 'zlib-populate'"
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-src
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-build
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/tmp
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src
	/usr/local/bin/cmake -E make_directory /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp
	/usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-mkdir

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-patch: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-update
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "No patch step for 'zlib-populate'"
	/usr/local/bin/cmake -E echo_append
	/usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-patch

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-update:
.PHONY : zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-update

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-test: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-install
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "No test step for 'zlib-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-build && /usr/local/bin/cmake -E echo_append
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-build && /usr/local/bin/cmake -E touch /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-test

zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-update: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-download
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Performing update step for 'zlib-populate'"
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-src && /usr/local/bin/cmake -P /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/zlib-populate-prefix/tmp/zlib-populate-gitupdate.cmake

zlib-populate: CMakeFiles/zlib-populate
zlib-populate: CMakeFiles/zlib-populate-complete
zlib-populate: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-build
zlib-populate: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-configure
zlib-populate: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-download
zlib-populate: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-install
zlib-populate: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-mkdir
zlib-populate: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-patch
zlib-populate: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-test
zlib-populate: zlib-populate-prefix/src/zlib-populate-stamp/zlib-populate-update
zlib-populate: CMakeFiles/zlib-populate.dir/build.make
.PHONY : zlib-populate

# Rule to build all files generated by this target.
CMakeFiles/zlib-populate.dir/build: zlib-populate
.PHONY : CMakeFiles/zlib-populate.dir/build

CMakeFiles/zlib-populate.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/zlib-populate.dir/cmake_clean.cmake
.PHONY : CMakeFiles/zlib-populate.dir/clean

CMakeFiles/zlib-populate.dir/depend:
	cd /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild /nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/thirdparty/zlib-subbuild/CMakeFiles/zlib-populate.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/zlib-populate.dir/depend

