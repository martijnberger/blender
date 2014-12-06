

set(CERES_PATH ${CMAKE_SOURCE_DIR}/extern/libmv/)

# make GLog a separate target, so it can be used for gtest as well.
if(WITH_LIBMV OR WITH_GTESTS OR WITH_CYCLES_LOGGING)
        # We compile GLog together with GFlag so we don't worry about
        # adding extra lib to linker.
        set(GLOG_SRC
                ${CERES_PATH}third_party/gflags/gflags.cc
                ${CERES_PATH}third_party/gflags/gflags_completions.cc
                ${CERES_PATH}third_party/gflags/gflags_reporting.cc

                ${CERES_PATH}third_party/gflags/config.h
                ${CERES_PATH}third_party/gflags/gflags/gflags_completions.h
                ${CERES_PATH}third_party/gflags/gflags/gflags_declare.h
                ${CERES_PATH}third_party/gflags/gflags/gflags.h
                ${CERES_PATH}third_party/gflags/mutex.h
                ${CERES_PATH}third_party/gflags/util.h
        )

        if(WIN32)
                list(APPEND GLOG_SRC
                        ${CERES_PATH}third_party/glog/src/logging.cc
                        ${CERES_PATH}third_party/glog/src/raw_logging.cc
                        ${CERES_PATH}third_party/glog/src/utilities.cc
                        ${CERES_PATH}third_party/glog/src/vlog_is_on.cc
                        ${CERES_PATH}third_party/glog/src/windows/port.cc

                        ${CERES_PATH}third_party/glog/src/utilities.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_generic-inl.h
                        ${CERES_PATH}third_party/glog/src/stacktrace.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_x86_64-inl.h
                        ${CERES_PATH}third_party/glog/src/base/googleinit.h
                        ${CERES_PATH}third_party/glog/src/base/mutex.h
                        ${CERES_PATH}third_party/glog/src/base/commandlineflags.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_powerpc-inl.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_x86-inl.h
                        ${CERES_PATH}third_party/glog/src/config.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_libunwind-inl.h
                        ${CERES_PATH}third_party/glog/src/windows/glog/raw_logging.h
                        ${CERES_PATH}third_party/glog/src/windows/glog/vlog_is_on.h
                        ${CERES_PATH}third_party/glog/src/windows/glog/logging.h
                        ${CERES_PATH}third_party/glog/src/windows/glog/log_severity.h
                        ${CERES_PATH}third_party/glog/src/windows/port.h
                        ${CERES_PATH}third_party/glog/src/windows/config.h
                )
        else()
                list(APPEND GLOG_SRC
                        ${CERES_PATH}third_party/glog/src/demangle.cc
                        ${CERES_PATH}third_party/glog/src/logging.cc
                        ${CERES_PATH}third_party/glog/src/raw_logging.cc
                        ${CERES_PATH}third_party/glog/src/signalhandler.cc
                        ${CERES_PATH}third_party/glog/src/symbolize.cc
                        ${CERES_PATH}third_party/glog/src/utilities.cc
                        ${CERES_PATH}third_party/glog/src/vlog_is_on.cc

                        ${CERES_PATH}third_party/glog/src/base/commandlineflags.h
                        ${CERES_PATH}third_party/glog/src/base/googleinit.h
                        ${CERES_PATH}third_party/glog/src/base/mutex.h
                        ${CERES_PATH}third_party/glog/src/config_freebsd.h
                        ${CERES_PATH}third_party/glog/src/config.h
                        ${CERES_PATH}third_party/glog/src/config_hurd.h
                        ${CERES_PATH}third_party/glog/src/config_linux.h
                        ${CERES_PATH}third_party/glog/src/config_mac.h
                        ${CERES_PATH}third_party/glog/src/demangle.h
                        ${CERES_PATH}third_party/glog/src/glog/logging.h
                        ${CERES_PATH}third_party/glog/src/glog/log_severity.h
                        ${CERES_PATH}third_party/glog/src/glog/raw_logging.h
                        ${CERES_PATH}third_party/glog/src/glog/vlog_is_on.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_generic-inl.h
                        ${CERES_PATH}third_party/glog/src/stacktrace.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_libunwind-inl.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_powerpc-inl.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_x86_64-inl.h
                        ${CERES_PATH}third_party/glog/src/stacktrace_x86-inl.h
                        ${CERES_PATH}third_party/glog/src/symbolize.h
                        ${CERES_PATH}third_party/glog/src/utilities.h
                )
        endif()

        set(GLOG_INC
                ${CERES_PATH}third_party/gflags
                ${CERES_PATH}third_party/glog/src
        )

endif()



set(INC
	.
	../device
	../kernel
	../kernel/svm
	../bvh
	../util
	../render
	../subd
)
set(INC_SYS
)

# NOTE: LIBRARIES contains all the libraries which are common
# across release and debug build types, stored in a linking order.
set(LIBRARIES
	cycles_device
	cycles_kernel
	cycles_render
	cycles_bvh
	cycles_subd
	cycles_util
	${BLENDER_GL_LIBRARIES}
	${CYCLES_APP_GLEW_LIBRARY}
	${PNG_LIBRARIES}
	${JPEG_LIBRARIES}
	${ZLIB_LIBRARIES}
	${TIFF_LIBRARY}
	${PTHREADS_LIBRARIES}
	extern_clew
	extern_cuew
)

if(WITH_CYCLES_OSL)
	list(APPEND LIBRARIES cycles_kernel_osl)
endif()

if(CYCLES_STANDALONE_REPOSITORY)
	if(WITH_CYCLES_LOGGING)
		list(APPEND LIBRARIES
			${GLOG_LIBRARIES}
			${GFLAGS_LIBRARIES}
		)
	endif()
else()
	list(APPEND LIBRARIES bf_intern_glew_mx)
	if(WITH_CYCLES_LOGGING)
		list(APPEND LIBRARIES extern_glog)
	endif()
endif()

if(WITH_CYCLES_STANDALONE AND WITH_CYCLES_STANDALONE_GUI)
	list(APPEND LIBRARIES ${GLUT_LIBRARIES})
endif()

# Common configuration.

link_directories(${OPENIMAGEIO_LIBPATH}
                 ${BOOST_LIBPATH}
                 ${PNG_LIBPATH}
                 ${JPEG_LIBPATH}
                 ${ZLIB_LIBPATH}
                 ${TIFF_LIBPATH}
                 ${OPENEXR_LIBPATH})

add_definitions(${GL_DEFINITIONS})

include_directories(${INC})
include_directories(SYSTEM ${INC_SYS})

# Make sure given target is linked against proper libraries
# which varies across debug and release build types.
#
# This will also make sure dependencies of that libraries
# are sent to the linker after them.
#
# TODO(sergey): Think of a better place for this?
macro(cycles_target_link_libraries target)
	target_link_libraries(${target} ${LIBRARIES})
	if(WITH_CYCLES_OSL)
		target_link_libraries_decoupled(${target} OSL_LIBRARIES)
		if(MSVC)
			target_link_libraries_debug(${target} "${LLVM_LIBRARIES_DEBUG}")
			target_link_libraries_optimized(${target} "${LLVM_LIBRARIES}")
		else()
			target_link_libraries(${target} ${LLVM_LIBRARIES})
		endif()
	endif()
	target_link_libraries_decoupled(${target} OPENIMAGEIO_LIBRARIES)
	target_link_libraries_decoupled(${target} OPENEXR_LIBRARIES)
	target_link_libraries(
		${target}
		${PUGIXML_LIBRARIES}
		${BOOST_LIBRARIES}
		${CMAKE_DL_LIBS}
		${PLATFORM_LINKLIBS}
	)
endmacro()

# Application build targets

if(WITH_CYCLES_STANDALONE)
	set(SRC
		cycles_standalone.cpp
		cycles_xml.cpp
		cycles_xml.h
	)
	add_executable(cycles ${SRC})
	cycles_target_link_libraries(cycles)

    if(UNIX AND NOT APPLE)
		set_target_properties(cycles PROPERTIES INSTALL_RPATH $ORIGIN/lib)
	endif()
	unset(SRC)
endif()

if(WITH_CYCLES_NETWORK)
	set(SRC
		cycles_server.cpp
	)
	add_executable(cycles_server ${SRC})
	cycles_target_link_libraries(cycles_server)

	if(UNIX AND NOT APPLE)
                set_target_properties(cycles_server PROPERTIES INSTALL_RPATH $ORIGIN/lib)
	endif()
	unset(SRC)
endif()
