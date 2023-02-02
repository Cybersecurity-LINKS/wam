if (NOT __CURL_INCLUDED) 
    set(__CURL_INCLUDED TRUE) 
    set(curl_src_dir ${PROJECT_BINARY_DIR}/curl/src/curl) 
    
    
    set(OPENSSL_SOURCE_DIR ${PROJECT_BINARY_DIR}/openssl-src)
    #set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-src) # default path by CMake
    set(OPENSSL_INSTALL_DIR ${PROJECT_BINARY_DIR}/openssl)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
    set(OPENSSL_CONFIGURE_COMMAND ${OPENSSL_SOURCE_DIR}/Configure)

    ExternalProject_Add(
        ext_OpenSSL
        DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
        DOWNLOAD_NAME openssl-1.1.1q.tar.gz
        URL https://www.openssl.org/source/old/1.1.1/openssl-1.1.1q.tar.gz

        SOURCE_DIR ${OPENSSL_SOURCE_DIR}
        #GIT_REPOSITORY https://github.com/openssl/openssl.git
        #GIT_TAG OpenSSL_1_1_1q
        USES_TERMINAL_DOWNLOAD TRUE
        #OPENSSL_LIBADD=-ldl
        CONFIGURE_COMMAND
        ${OPENSSL_CONFIGURE_COMMAND} linux64-riscv64 no-asm no-threads no-shared no-posix-io
        --cross-compile-prefix=riscv64-unknown-linux-gnu-
        --prefix=${OPENSSL_INSTALL_DIR} 
        --openssldir=${OPENSSL_INSTALL_DIR}
        
        BUILD_COMMAND make -j20
        TEST_COMMAND ""
        INSTALL_COMMAND ""
        INSTALL_COMMAND make install_sw
        #INSTALL_DIR ${OPENSSL_INSTALL_DIR}
    )

    ExternalProject_Add( 
        curl 
        PREFIX ${PROJECT_BINARY_DIR}/curl 
        DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download 
        DOWNLOAD_NAME curl-7.68.0.tar.gz 
        URL https://github.com/curl/curl/releases/download/curl-7_68_0/curl-7.68.0.tar.gz 
        BUILD_IN_SOURCE TRUE 

        CFLAGS="-I${OPENSSL_INSTALL_DIR}/include"
        LDFLAGS="-static -L${OPENSSL_INSTALL_DIR}/lib"
        LIBS="-ldl"
  
        CONFIGURE_COMMAND 
            ${curl_src_dir}/configure 
            --prefix=${CMAKE_INSTALL_PREFIX}  
            --host=riscv64-unknown-linux-gnu 
            --disable-pthreads 
            --with-ssl=/home/ubuntu18/buildOpenSSL 
            --disable-threaded-resolver 
            --disable-shared 
            CC=${CMAKE_C_COMPILER} 
            CXX=${CMAKE_CXX_COMPILER}
            --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt
            --with-ca-path=/etc/ssl/certs

        INSTALL_DIR ${CMAKE_INSTALL_PREFIX}
        INSTALL_COMMAND make install
        
        # CMAKE_ARGS 
        # -DBUILD_SHARED_LIBS:STRING=Off
        # -DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_INSTALL_PREFIX} 
        # -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER} 
        # -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    )

    add_dependencies(curl ext_OpenSSL)
endif()