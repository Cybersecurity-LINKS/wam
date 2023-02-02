# Copyright (c) 2013, The Regents of the University of California (Regents).
# All Rights Reserved.
# Source: https://github.com/keystone-enclave/keystone

macro(global_set Name Value)
    #  message("set ${Name} to " ${ARGN})
    set(${Name} "${Value}" CACHE STRING "NoDesc" FORCE)
endmacro()

macro(check_compiler target)
  message(STATUS "Check for working C compiler: ${target}")
  execute_process(
    COMMAND ${target} -print-file-name=crt.o
    OUTPUT_FILE OUTPUT
    RESULT_VARIABLE ERROR)

  if ("${ERROR}" STREQUAL 0)
    message(STATUS "Check for working C compiler: ${target} -- works")
  else()
    message(FATAL_ERROR "Check for working C compiler: ${target} -- not working")
  endif()
endmacro()

macro(use_riscv_toolchain bits)
  set(cross_compile riscv${bits}-unknown-linux-gnu-)

  execute_process(
    COMMAND which ${cross_compile}gcc
    OUTPUT_VARIABLE CROSSCOMPILE
    RESULT_VARIABLE ERROR)

  if (NOT "${ERROR}" STREQUAL 0)
    message(FATAL_ERROR "RISCV Toochain is not found")
  endif()

  string(STRIP ${CROSSCOMPILE} CROSSCOMPILE)
  string(REPLACE "gcc" "" CROSSCOMPILE ${CROSSCOMPILE})

  message(STATUS "Tagret tripplet: ${CROSSCOMPILE}")

  set(CC              ${CROSSCOMPILE}gcc)
  set(CXX             ${CROSSCOMPILE}g++)
  set(LD              ${CROSSCOMPILE}ld)
  set(AR              ${CROSSCOMPILE}ar)
  set(OBJCOPY         ${CROSSCOMPILE}objcopy)
  set(OBJDUMP         ${CROSSCOMPILE}objdump)
  set(CFLAGS          "-Wall ") # -Werror")

  global_set(CMAKE_C_COMPILER        ${CC}${EXT})
  global_set(CMAKE_ASM_COMPILER        ${CC}${EXT})
  global_set(CMAKE_CXX_COMPILER      ${CXX}${EXT})
  global_set(CMAKE_LINKER            ${LD}${EXT})
  global_set(CMAKE_AR                ${AR}${EXT})
  global_set(CMAKE_OBJCOPY           ${OBJCOPY}${EXT})
  global_set(CMAKE_OBJDUMP           ${OBJDUMP}${EXT})
  global_set(CMAKE_C_FLAGS           ${CMAKE_C_FLAGS} ${CFLAGS})

  check_compiler(${CMAKE_C_COMPILER})
  check_compiler(${CMAKE_CXX_COMPILER})

  global_set(CMAKE_C_COMPILER_WORKS      1)
  global_set(CMAKE_CXX_COMPILER_WORKS    1)

  global_set(CMAKE_SYSTEM_NAME    "Linux")

endmacro()