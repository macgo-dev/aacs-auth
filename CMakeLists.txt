cmake_minimum_required(VERSION 2.8.12)

project(aacs-auth C)

set(LIBRESSL_SKIP_INSTALL ON CACHE INTERNAL "LIBRESSL_SKIP_INSTALL" FORCE)
set(LIBRESSL_APPS OFF CACHE INTERNAL "LIBRESSL_APPS" FORCE)
set(LIBRESSL_TESTS OFF CACHE INTERNAL "LIBRESSL_TESTS" FORCE)
add_subdirectory(libressl)

set(SOURCES main.c mmc.h mmc.c)
set(LIBS crypto)

if(APPLE)
    set(SOURCES ${SOURCES} mmc_mac.c)
    set(LIBS ${LIBS} "-framework CoreFoundation" "-framework IOKit")
endif()

if(WIN32)
    set(SOURCES ${SOURCES} mmc_win.c)
    set(LIBS ${LIBS} ws2_32)
endif()

add_executable(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE libressl/include)
target_link_libraries(${PROJECT_NAME} ${LIBS})
