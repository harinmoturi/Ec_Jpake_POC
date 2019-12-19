# Sets the minimum version of CMake required to build your native library.
# This ensures that a certain set of CMake features is available to
# your build.

cmake_minimum_required(VERSION 3.4.1)

# Specifies a library name, specifies whether the library is STATIC or
# SHARED, and provides relative paths to the source code. You can
# define multiple libraries by adding multiple add_library() commands,
# and CMake builds them for you. When you build your app, Gradle
# automatically packages shared libraries with your APK.

file(GLOB SOURCE_FILES src/main/cpp/**/*.c)
file(GLOB HEADER_FILES src/main/cpp/**/*.h)

add_library( # Specifies the name of the library.
             ecjpake

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
        src/main/cpp/ec-jpake/ec-jpake.c src/main/cpp/ec-jpake/pointCalc.c src/main/cpp/ec-jpake/sha256_.c src/main/cpp/micro-ecc/uECC.c src/main/cpp/ec-jpake/wrap.c src/main/cpp/ec-jpake/speke_java.c)

target_link_libraries(ecjpake
        android
        log)