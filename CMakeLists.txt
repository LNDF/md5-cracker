cmake_minimum_required(VERSION 3.10)

# Set the project name
project(md5-cracker C)

# Specify the C standard
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(md5-cracker main.c)

# Link against OpenSSL
target_link_libraries(md5-cracker OpenSSL::SSL OpenSSL::Crypto)