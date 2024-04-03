cmake_minimum_required(VERSION 3.14)

project(cc_srv LANGUAGES C)

#set(CMAKE_AUTOUIC ON)
#set(CMAKE_AUTOMOC ON)
#set(CMAKE_AUTORCC ON)
#set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)

MESSAGE( STATUS "cc_srv Start" )

add_executable(cc_srv
	cc_proc.h
	cc_proc.c
	cc_tools.h
	cc_tools.c
	cc_work.c
	cc_work.h
	cc_srv.c
        ../ca_cc_srv.cfg
	)

if(WIN32)
    include_directories( ../../PKILib
        "c:/msys64/mingw64/include"
        ../../PKILib/lib/win64/winsparkle/include )

    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug
        ../../lib/win64/debug/openssl3/lib64
        ../../PKILib/lib/win64/winsparkle/x64/Release
        "C:/msys64/mingw64/lib" )
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release
        ../../lib/win64/openssl3/lib64
        ../../PKILib/lib/win64/winsparkle/x64/Release
        "C:/msys64/mingw64/lib" )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        PKILib crypto ssl ltdl sqlite3 ldap lber ws2_32 )

elseif(APPLE)
    include_directories( ../../PKILib
        ../../lib/mac/openssl3/include
        /usr/local/include )

    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Debug
        ../../lib/mac/debug/openssl3/lib
        /usr/local/lib )
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Release
        ../../lib/mac/openssl3/lib
        /usr/local/lib )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        PKILib crypto ssl ltdl sqlite3 ldap lber )
else()
    message( STATUS "Linux Env" )

    include_directories(
        ../../lib/linux/openssl/include
        ../../PKILib
        "/usr/local/include" )

    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Debug
        ../../lib/linux/debug/openssl3/lib64
        "/usr/local/lib" )
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Release
        ../../lib/linux/openssl3/lib64
        "/usr/local/lib" )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        PKILib crypto ssl ltdl sqlite3 ldap lber pthread )

    target_compile_definitions( ${PROJECT_NAME} PRIVATE USE_PRC )
endif()
