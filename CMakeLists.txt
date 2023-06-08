# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

cmake_minimum_required(VERSION 3.12)

# ============= Linktest shared ===============
project(linktest VERSION 1.0)

add_library(link STATIC include/liblink.h src/liblink.c)
target_include_directories(link PUBLIC ${PROJECT_SOURCE_DIR}/include/)

macro(m_install)
	install(TARGETS ${arg1}
		CONFIGURATIONS Debug
		RUNTIME DESTINATION bin)
	install(TARGETS ${arg1}
		CONFIGURATIONS Release
		RUNTIME DESTINATION bin)
endmacro()

set(PROJECT_INCLUDES ${PROJECT_SOURCE_DIR}/include ${PROJECT_BINARY_DIR}/include)

# ============= tstest ===============
project(tstest VERSION 1.0)

# ---- BUILD ----
add_executable(tstest)
target_sources(tstest PRIVATE src/ptp_message.c src/extts.c src/pkt.c src/tstest.c)

target_include_directories(tstest PUBLIC ${PROJECT_INCLUDES})
target_link_libraries(tstest PUBLIC)
m_install(tstest)


# ============= Configure ===============
configure_file(include/version.h.in include/version.h)

