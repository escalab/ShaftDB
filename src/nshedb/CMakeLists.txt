set(NSHEDB_SOURCE_FILES ${NSHEDB_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/comparator.cpp
    ${CMAKE_CURRENT_LIST_DIR}/predicates.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/comparator.h
        ${CMAKE_CURRENT_LIST_DIR}/predicates.h
        ${CMAKE_CURRENT_LIST_DIR}/nshedb.h
        ${CMAKE_CURRENT_LIST_DIR}/utils.h
    DESTINATION
        ${NSHEDB_INCLUDES_INSTALL_DIR}/nshedb
)
set(NSHEDB_SOURCE_FILES ${NSHEDB_SOURCE_FILES} PARENT_SCOPE)
