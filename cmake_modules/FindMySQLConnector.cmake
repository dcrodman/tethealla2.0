# - Try to find Iconv 
# Once done this will define 
#
#  MYSQLCONNECTORC_FOUND - system has Jansson
#  MYSQLCONNECTORC_INCLUDE_DIRS - the Jansson include directory
#  MYSQLCONNECTORC_LIBRARIES - Link these to use Jansson
#

if (MYSQLCONNECTORC_LIBRARIES AND MYSQLCONNECTORC_INCLUDE_DIRS)
  set(MYSQLCONNECTORC_FOUND TRUE)
else (MYSQLCONNECTORC_LIBRARIES AND MYSQLCONNECTORC_INCLUDE_DIRS)
  find_path(MYSQLCONNECTORC_INCLUDE_DIR
    NAMES
      mysql.h
    PATHS
      /usr/local/mysql/include
      /opt/local/mysql/include
      /usr/include
      /usr/local/include
      /opt/local/include
  )

find_library(MYSQLCONNECTORC_LIBRARY
    NAMES
      mysqlclient
    PATHS
      /usr/local/mysql/lib
      /opt/local/mysql/lib
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

set(MYSQLCONNECTORC_INCLUDE_DIRS ${MYSQLCONNECTORC_INCLUDE_DIR})

if (MYSQLCONNECTORC_LIBRARY)
  set(MYSQLCONNECTORC_LIBRARIES 
    ${MYSQLCONNECTORC_LIBRARIES}
    ${MYSQLCONNECTORC_LIBRARY})
endif (MYSQLCONNECTORC_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MySQLConnectorC
  DEFAULT_MSG
  MYSQLCONNECTORC_INCLUDE_DIR
  MYSQLCONNECTORC_LIBRARY)

if(MYSQLCONNECTORC_FOUND)
  set(MYSQLCONNECTORC_INCLUDE_DIRS "${MYSQLCONNECTORC_INCLUDE_DIR}")
  set(MYSQLCONNECTORC_LIBRARIES "${MYSQLCONNECTORC_LIBRARIES}")
  mark_as_advanced(MYSQLCONNECTORC_ROOT_DIR)
endif(MYSQLCONNECTORC_FOUND)

endif (MYSQLCONNECTORC_LIBRARIES AND MYSQLCONNECTORC_INCLUDE_DIRS)

