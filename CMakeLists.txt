cmake_minimum_required(VERSION 2.8)
project(socketplug_core)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=c11")
set(CMAKE_C_COMPILER "clang")


#set(SOURCE_DIR src)
#set(SOURCE_FILES main.c)
add_library(socketplug_core src/socketplug.h src/socketplug.c src/bstrlib.h src/bstrlib.c src/util.h src/internals.h src/internals.c src/http.h src/http.c)
#set(LIB_DIR lib)

SET(requiredlibs)

FIND_PACKAGE(CURL)
IF(CURL_FOUND)
  INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR})
  SET(requiredlibs ${requiredlibs} ${CURL_LIBRARIES} )
ELSE(CURL_FOUND)
  MESSAGE(FATAL_ERROR "Could not find the CURL library and development files.")
ENDIF(CURL_FOUND)

FIND_PACKAGE(PCRE)
IF(PCRE_FOUND)
  INCLUDE_DIRECTORIES(${PCRE_INCLUDE_DIR})
  SET(requiredlibs ${requiredlibs} ${PCRE_LIBRARIES} )
ELSE(PCRE_FOUND)
  MESSAGE(FATAL_ERROR "Could not find the PCRE library and development files.")
ENDIF(PCRE_FOUND)

FIND_PACKAGE(LIBWEBSOCKETS)
IF(LIBWEBSOCKETS_FOUND)
  INCLUDE_DIRECTORIES(${LIBWEBSOCKETS_INCLUDE_DIR})
  SET(requiredlibs ${requiredlibs} ${LIBWEBSOCKETS_LIBRARIES} )
ELSE(LIBWEBSOCKETS_FOUND)
  MESSAGE(FATAL_ERROR "Could not find the LIBWEBSOCKETS library and development files.")
ENDIF(LIBWEBSOCKETS_FOUND)

FIND_PACKAGE(YAJL)
IF(YAJL_FOUND)
  INCLUDE_DIRECTORIES(${YAJL_INCLUDE_DIR})
  SET(requiredlibs ${requiredlibs} ${YAJL_LIBRARY} )
ELSE(YAJL_FOUND)
  MESSAGE(FATAL_ERROR "Could not find the YAJL library and development files.")
ENDIF(YAJL_FOUND)


target_link_libraries (socketplug_core ${requiredlibs})

add_executable(Example src/main.c)
target_link_libraries(Example socketplug_core)

#add_library(${LIB_DIR}/bstring/bstrlib.c)

