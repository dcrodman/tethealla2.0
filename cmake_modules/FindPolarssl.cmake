# - Try to find POLARSSL
# Once done this will define
#
#  POLARSSL_FOUND - system has POLARSSL
#  POLARSSL_INCLUDE_DIRS - the Polarssl include directory
#  POLARSSL_LIBRARIES - Link these to use Polarssl
#
#  Copyright (c) 2014 Andrew Rodman <dcrodman@gmail.com>
#  Adopted from FindJansson.cmake by Lee Hambley.
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#

if (POLARSSL_LIBRARIES AND POLARSSL_INCLUDE_DIRS)
  # in cache already
  set(POLARSSL_FOUND TRUE)
else (POLARSSL_LIBRARIES AND POLARSSL_INCLUDE_DIRS)
  find_path(POLARSSL_INCLUDE_DIR
    NAMES
      polarssl
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
  )

find_library(POLARSSL_LIBRARY
    NAMES
      polarssl
      libpolarssl
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

set(POLARSSL_INCLUDE_DIRS ${POLARSSL_INCLUDE_DIR})

if (POLARSSL_LIBRARY)
  set(POLARSSL_LIBRARIES ${POLARSSL_LIBRARIES} ${POLARSSL_LIBRARY})
endif (POLARSSL_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(POLARSSL DEFAULT_MSG
    POLARSSL_LIBRARIES POLARSSL_INCLUDE_DIRS)

  # show the POLARSSL_INCLUDE_DIRS and POLARSSL_LIBRARIES variables only in the advanced view
  mark_as_advanced(POLARSSL_INCLUDE_DIRS POLARSSL_LIBRARIES)

endif (POLARSSL_LIBRARIES AND POLARSSL_INCLUDE_DIRS)

