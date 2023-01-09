cmake_minimum_required(VERSION 3.10)
project(WAM VERSION 1.0)


link_directories( "${CMAKE_INSTALL_PREFIX}/lib" 
                  "${CMAKE_INSTALL_PREFIX}/iota.c/src/client" 
				  "${CMAKE_INSTALL_PREFIX}/iota.c/src/core"
				  "${CMAKE_INSTALL_PREFIX}/iota.c/src/crypto" )
add_library(WAM "WAM.c")


add_subdirectory("${CMAKE_SOURCE_DIR}/iota.c")
target_include_directories( WAM PUBLIC 
                            "${CMAKE_INSTALL_PREFIX}/include" 
							"${CMAKE_INSTALL_PREFIX}/include/cjson" 
							"${CMAKE_SOURCE_DIR}/iota.c/src" 
							"${CMAKE_SOURCE_DIR}" )
target_link_libraries(WAM iota_client)
add_dependencies(WAM iota_client)


set( APP_EXE ExampleWAM )
add_executable( ${APP_EXE} "example.c" ) 
target_link_libraries( ${APP_EXE} WAM )


