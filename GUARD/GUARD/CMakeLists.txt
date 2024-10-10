project(GUARD)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS *.cpp *.hpp)

add_executable(${PROJECT_NAME}
	${SOURCES}
)
