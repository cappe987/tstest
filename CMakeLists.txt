# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

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
target_sources(tstest PRIVATE src/liblink.c src/timestamping.c src/ptp_message.c src/extts.c src/pkt.c src/tstest.c src/delay.c src/check.c)

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
	unshare -r -n ${PROJECT_SOURCE_DIR}/test/test.sh ${PROJECT_BINARY_DIR}/tstest $(t)
	DEPENDS ${PROJECT_BINARY_DIR}/tstest
	)

# ============= Configure ===============
configure_file(include/version.h.in include/version.h)

