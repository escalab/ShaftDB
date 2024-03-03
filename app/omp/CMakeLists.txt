find_package(OpenMP REQUIRED)

add_executable(tpch1_omp)
target_sources(tpch1_omp
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch1_omp.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)


add_executable(tpch4_omp)
target_sources(tpch4_omp
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch4_omp.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)


add_executable(tpch6_omp)
target_sources(tpch6_omp
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch6_omp.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)



add_executable(tpch8_omp)
target_sources(tpch8_omp
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch8_omp.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)

add_executable(tpch12_omp)
target_sources(tpch12_omp
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch12_omp.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)



add_executable(tpch14_omp)
target_sources(tpch14_omp
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch14_omp.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)

add_executable(tpch17_omp)
target_sources(tpch17_omp
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch17_omp.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)

add_executable(tpch19_omp)
target_sources(tpch19_omp
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch19_omp.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)


target_link_libraries(tpch1_omp PRIVATE SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(tpch4_omp PRIVATE SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(tpch6_omp PRIVATE SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(tpch8_omp PRIVATE SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(tpch12_omp PRIVATE SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(tpch14_omp PRIVATE SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(tpch17_omp PRIVATE SEAL::seal OpenMP::OpenMP_CXX)
target_link_libraries(tpch19_omp PRIVATE SEAL::seal OpenMP::OpenMP_CXX)