# Install script for directory: /nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/SEAL-4.1/seal" TYPE FILE FILES
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/batchencoder.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/ciphertext.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/ckks.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/modulus.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/context.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/decryptor.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/dynarray.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/encryptionparams.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/encryptor.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/evaluator.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/galoiskeys.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/keygenerator.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/kswitchkeys.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/memorymanager.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/plaintext.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/publickey.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/randomgen.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/randomtostd.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/relinkeys.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/seal.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/secretkey.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/serializable.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/serialization.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/valcheck.h"
    "/nfshome/bjung022/Project/ShaftDB/thirdparty/SEAL/native/src/seal/version.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/nfshome/bjung022/Project/ShaftDB/build/thirdparty/SEAL/native/src/seal/util/cmake_install.cmake")

endif()

