# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ubuntu/plugin

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ubuntu/plugin

# Include any dependencies generated for this target.
include CMakeFiles/p.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/p.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/p.dir/flags.make

CMakeFiles/p.dir/Plugin.c.o: CMakeFiles/p.dir/flags.make
CMakeFiles/p.dir/Plugin.c.o: Plugin.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/ubuntu/plugin/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/p.dir/Plugin.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/p.dir/Plugin.c.o   -c /home/ubuntu/plugin/Plugin.c

CMakeFiles/p.dir/Plugin.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/p.dir/Plugin.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -E /home/ubuntu/plugin/Plugin.c > CMakeFiles/p.dir/Plugin.c.i

CMakeFiles/p.dir/Plugin.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/p.dir/Plugin.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -S /home/ubuntu/plugin/Plugin.c -o CMakeFiles/p.dir/Plugin.c.s

CMakeFiles/p.dir/Plugin.c.o.requires:
.PHONY : CMakeFiles/p.dir/Plugin.c.o.requires

CMakeFiles/p.dir/Plugin.c.o.provides: CMakeFiles/p.dir/Plugin.c.o.requires
	$(MAKE) -f CMakeFiles/p.dir/build.make CMakeFiles/p.dir/Plugin.c.o.provides.build
.PHONY : CMakeFiles/p.dir/Plugin.c.o.provides

CMakeFiles/p.dir/Plugin.c.o.provides.build: CMakeFiles/p.dir/Plugin.c.o

CMakeFiles/p.dir/security_default.c.o: CMakeFiles/p.dir/flags.make
CMakeFiles/p.dir/security_default.c.o: security_default.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/ubuntu/plugin/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/p.dir/security_default.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/p.dir/security_default.c.o   -c /home/ubuntu/plugin/security_default.c

CMakeFiles/p.dir/security_default.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/p.dir/security_default.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -E /home/ubuntu/plugin/security_default.c > CMakeFiles/p.dir/security_default.c.i

CMakeFiles/p.dir/security_default.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/p.dir/security_default.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -S /home/ubuntu/plugin/security_default.c -o CMakeFiles/p.dir/security_default.c.s

CMakeFiles/p.dir/security_default.c.o.requires:
.PHONY : CMakeFiles/p.dir/security_default.c.o.requires

CMakeFiles/p.dir/security_default.c.o.provides: CMakeFiles/p.dir/security_default.c.o.requires
	$(MAKE) -f CMakeFiles/p.dir/build.make CMakeFiles/p.dir/security_default.c.o.provides.build
.PHONY : CMakeFiles/p.dir/security_default.c.o.provides

CMakeFiles/p.dir/security_default.c.o.provides.build: CMakeFiles/p.dir/security_default.c.o

# Object files for target p
p_OBJECTS = \
"CMakeFiles/p.dir/Plugin.c.o" \
"CMakeFiles/p.dir/security_default.c.o"

# External object files for target p
p_EXTERNAL_OBJECTS =

libp.so: CMakeFiles/p.dir/Plugin.c.o
libp.so: CMakeFiles/p.dir/security_default.c.o
libp.so: CMakeFiles/p.dir/build.make
libp.so: CMakeFiles/p.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C shared library libp.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/p.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/p.dir/build: libp.so
.PHONY : CMakeFiles/p.dir/build

CMakeFiles/p.dir/requires: CMakeFiles/p.dir/Plugin.c.o.requires
CMakeFiles/p.dir/requires: CMakeFiles/p.dir/security_default.c.o.requires
.PHONY : CMakeFiles/p.dir/requires

CMakeFiles/p.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/p.dir/cmake_clean.cmake
.PHONY : CMakeFiles/p.dir/clean

CMakeFiles/p.dir/depend:
	cd /home/ubuntu/plugin && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ubuntu/plugin /home/ubuntu/plugin /home/ubuntu/plugin /home/ubuntu/plugin /home/ubuntu/plugin/CMakeFiles/p.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/p.dir/depend

