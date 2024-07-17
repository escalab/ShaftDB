add_executable(tpch1)
target_sources(tpch1
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch1.cpp
        ${NSHEDB_INCLUDES_DIR}/comparator.cpp
        ${NSHEDB_INCLUDES_DIR}/predicates.cpp
)


add_executable(tpch4)
target_sources(tpch4
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch4.cpp
        ${NSHEDB_INCLUDES_DIR}/comparator.cpp
        ${NSHEDB_INCLUDES_DIR}/predicates.cpp
)


add_executable(tpch6)
target_sources(tpch6
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch6.cpp
        ${NSHEDB_INCLUDES_DIR}/comparator.cpp
        ${NSHEDB_INCLUDES_DIR}/predicates.cpp
)

add_executable(tpch8)
target_sources(tpch8
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch8.cpp
        ${NSHEDB_INCLUDES_DIR}/comparator.cpp
        ${NSHEDB_INCLUDES_DIR}/predicates.cpp
)

add_executable(tpch12)
target_sources(tpch12
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch12.cpp
        ${NSHEDB_INCLUDES_DIR}/comparator.cpp
        ${NSHEDB_INCLUDES_DIR}/predicates.cpp
)


add_executable(tpch14)
target_sources(tpch14
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch14.cpp
        ${NSHEDB_INCLUDES_DIR}/comparator.cpp
        ${NSHEDB_INCLUDES_DIR}/predicates.cpp
)


add_executable(tpch17)
target_sources(tpch17
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch17.cpp
        ${NSHEDB_INCLUDES_DIR}/comparator.cpp
        ${NSHEDB_INCLUDES_DIR}/predicates.cpp
)


add_executable(tpch19)
target_sources(tpch19
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch19.cpp
        ${NSHEDB_INCLUDES_DIR}/comparator.cpp
        ${NSHEDB_INCLUDES_DIR}/predicates.cpp
)

target_link_libraries(tpch1 PRIVATE SEAL::seal)
target_link_libraries(tpch4 PRIVATE SEAL::seal)
target_link_libraries(tpch6 PRIVATE SEAL::seal)
target_link_libraries(tpch8 PRIVATE SEAL::seal)
target_link_libraries(tpch12 PRIVATE SEAL::seal)
target_link_libraries(tpch14 PRIVATE SEAL::seal)
target_link_libraries(tpch17 PRIVATE SEAL::seal)
target_link_libraries(tpch19 PRIVATE SEAL::seal)
