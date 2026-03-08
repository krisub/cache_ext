cmake_minimum_required(VERSION 3.10)
project(My_YCSB)

set(CMAKE_CXX_STANDARD 17)

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -g")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread,undefined -g")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")


find_package(yaml-cpp REQUIRED)
include_directories(${YAML_CPP_INCLUDE_DIR})
link_directories(/usr/local/lib64)
# Debug mode
# set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g -rdynamic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

# Export compile_commands.json for clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Enable all warnings and safety flags
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(
        # -Wall
        # -Wextra
        # -Wpedantic
        # -Wshadow
        # -Wnon-virtual-dtor
        # -Wold-style-cast
        # -Wcast-align
        # -Wunused
        # -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        # -Wformat=2
        # -Wimplicit-fallthrough
        # -Wmisleading-indentation
        # -Wduplicated-cond
        # -Wduplicated-branches
        # -Wlogical-op
        # -Wuseless-cast
        # -Wno-reorder
    )
elseif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_compile_options(
        /W4
        /WX
        /permissive-
        /sdl
        /Zc:__cplusplus
        /Zc:inline
        /Zc:forScope
        /Zc:rvalueCast
    )
endif()

include_directories(/usr/local/include)
include_directories(core/include)

set(CoreSource core/client.cpp
               core/measurement.cpp
               core/worker.cpp
               core/workload.cpp)

set(WiredTigerClientSource wiredtiger/wt_client.cpp)
add_executable(init_wt ${CoreSource} ${WiredTigerClientSource} wiredtiger/init_wt.cpp)
add_executable(run_wt ${CoreSource} ${WiredTigerClientSource} wiredtiger/run_wt.cpp)
target_link_libraries(init_wt /usr/local/lib/libwiredtiger.so pthread ${YAML_CPP_LIBRARIES})
target_link_libraries(run_wt /usr/local/lib/libwiredtiger.so pthread ${YAML_CPP_LIBRARIES})

# Add the same for RocksDB
set(RocksDBClientSource rocksdb/rocksdb_client.cpp)
add_executable(init_rocksdb ${CoreSource} ${RocksDBClientSource} rocksdb/init_rocksdb.cpp)
add_executable(run_rocksdb ${CoreSource} ${RocksDBClientSource} rocksdb/run_rocksdb.cpp)
target_link_libraries(init_rocksdb /usr/local/lib/librocksdb.so pthread ${YAML_CPP_LIBRARIES})
target_link_libraries(run_rocksdb /usr/local/lib/librocksdb.so pthread ${YAML_CPP_LIBRARIES})

# Add the same for LevelDB
set(LevelDBClientSource leveldb/leveldb_client.cpp)
add_executable(init_leveldb ${CoreSource} ${LevelDBClientSource} leveldb/init_leveldb.cpp)
add_executable(run_leveldb ${CoreSource} ${LevelDBClientSource} leveldb/run_leveldb.cpp)
target_link_libraries(init_leveldb leveldb snappy pthread bpf ${YAML_CPP_LIBRARIES})
target_link_libraries(run_leveldb leveldb snappy pthread bpf ${YAML_CPP_LIBRARIES})

# Add the same for IOTrace
set(IOTraceClientSource io_trace/io_trace_client.cpp io_trace/constants.cpp)
add_executable(run_io_trace ${CoreSource} ${IOTraceClientSource} io_trace/run_io_trace.cpp)
target_link_libraries(run_io_trace bpf ${YAML_CPP_LIBRARIES})


set(RedisClientSource redis/redis_client.cpp)
add_executable(init_redis ${CoreSource} ${RedisClientSource} redis/init_redis.cpp)
add_executable(run_redis ${CoreSource} ${RedisClientSource} redis/run_redis.cpp)
target_link_libraries(init_redis pthread hiredis ${YAML_CPP_LIBRARIES})
target_link_libraries(run_redis pthread hiredis ${YAML_CPP_LIBRARIES})

set(MemcachedClientSource memcached/memcached_client.cpp)
add_executable(init_memcached ${CoreSource} ${MemcachedClientSource} memcached/init_memcached.cpp)
add_executable(run_memcached ${CoreSource} ${MemcachedClientSource} memcached/run_memcached.cpp)
target_link_libraries(init_memcached pthread memcached ${YAML_CPP_LIBRARIES})
target_link_libraries(run_memcached pthread memcached ${YAML_CPP_LIBRARIES})

# NetLevelDB: TCP client to net_leveldb_server (page-cache-friendly networked LevelDB)
set(NetLevelDBClientSource net_leveldb/net_leveldb_client.cpp)
add_executable(init_net_leveldb ${CoreSource} ${NetLevelDBClientSource} net_leveldb/init_net_leveldb.cpp)
add_executable(run_net_leveldb ${CoreSource} ${NetLevelDBClientSource} net_leveldb/run_net_leveldb.cpp)
target_link_libraries(init_net_leveldb pthread ${YAML_CPP_LIBRARIES})
target_link_libraries(run_net_leveldb pthread ${YAML_CPP_LIBRARIES})

