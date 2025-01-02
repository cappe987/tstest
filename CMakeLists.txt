# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

cmake_minimum_required(VERSION 3.12)

# ============= Linktest shared ===============
project(tstest VERSION 1.0)

#add_library(link STATIC include/liblink.h src/liblink.c)
#target_include_directories(link PUBLIC ${PROJECT_SOURCE_DIR}/include/)

#macro(m_install)
#endmacro()

set(PROJECT_INCLUDES ${PROJECT_SOURCE_DIR}/include ${PROJECT_BINARY_DIR}/include)

# ============= tstest ===============
project(tstest VERSION 1.0)

# ---- BUILD ----
add_executable(tstest)
target_sources(tstest PRIVATE src/liblink.c src/timestamping.c src/ptp_message.c src/extts.c src/pkt.c src/tstest.c src/delay.c src/check.c src/tc.c src/stats.c)

target_include_directories(tstest PUBLIC ${PROJECT_INCLUDES})
target_link_libraries(tstest PUBLIC)

install(TARGETS tstest
	CONFIGURATIONS Debug
	RUNTIME DESTINATION bin)
install(TARGETS tstest
	CONFIGURATIONS Release
	RUNTIME DESTINATION bin)
#m_install(tstest)

add_custom_target(test
	COMMAND
	unshare -r -n ${PROJECT_SOURCE_DIR}/scripts/test.sh ${PROJECT_BINARY_DIR}/tstest $(t)
	DEPENDS ${PROJECT_BINARY_DIR}/tstest
	)

# Add separate command for pipeline since apparently `unshare` is
# problematic there on Ubuntu 24.04.
add_custom_target(pipeline_test
	COMMAND
	${PROJECT_SOURCE_DIR}/scripts/test.sh ${PROJECT_BINARY_DIR}/tstest $(t)
	DEPENDS ${PROJECT_BINARY_DIR}/tstest
	)

# ============= Configure ===============
configure_file(include/version.h.in include/version.h)


#project(tcalign VERSION 1.0)
##set(PROJECT_NAME_VERSION "${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")


## ---- PROJECT SETUP ----
##set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wpedantic -Wextra")

## ---- BUILD ----
#find_library (LIBNL_LIBRARY nl-3)
#find_library (LIBNL_GENL_LIBRARY nl-genl-3)

#set(LIBNL_LIBRARIES ${LIBNL_LIBRARY} ${LIBNL_GENL_LIBRARY})
#set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

##set(CMAKE_C_FLAGS
	##"${CMAKE_C_FLAGS} -Wall -Wpedantic -Wextra"
##)

#find_path (LIBNL_INCLUDE_DIR NAMES netlink/netlink.h PATH_SUFFIXES libnl3)
#include_directories(include ${LIBNL_INCLUDE_DIR})




#add_executable(tcalign)
#target_sources(tcalign PRIVATE src/tcalign.c)

#install(TARGETS tcalign
	#CONFIGURATIONS Debug
	#RUNTIME DESTINATION bin)
#install(TARGETS tcalign
	#CONFIGURATIONS Release
	#RUNTIME DESTINATION bin)

#target_link_libraries(tcalign PUBLIC gpiod ${LIBNL_LIBRARIES})

