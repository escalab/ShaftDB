add_executable(comparison)
target_sources(comparison
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/comparison.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)

add_executable(operator)
target_sources(operator
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/operator.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)


add_executable(tpch6_between)
target_sources(tpch6_between
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/tpch6_between.cpp
        ${SHAFTDB_INCLUDES_DIR}/comparator.cpp 
        ${SHAFTDB_INCLUDES_DIR}/predicates.cpp
)


target_link_libraries(comparison PRIVATE SEAL::seal)
target_link_libraries(operator PRIVATE SEAL::seal)
target_link_libraries(tpch6_between PRIVATE SEAL::seal)