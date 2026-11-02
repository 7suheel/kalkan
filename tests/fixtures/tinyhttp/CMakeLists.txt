cmake_minimum_required(VERSION 3.10)
project(tinyhttp VERSION 1.2.0 LANGUAGES C)
add_executable(tinyhttp src/main.c src/parser.c src/conn.c)
