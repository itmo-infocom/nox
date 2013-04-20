include ../../Make.vars 

CONFIGURE_DEPENCIES = $(srcdir)/Makefile.am

SWITCH_LIB_VERSION = 1:0:0

EXTRA_DIST =                                    \
    meta.json

pkglib_LTLIBRARIES =                            \
    switchqos.la    

switchqos_la_CPPFLAGS =                            \
    $(AM_CPPFLAGS)                              \
    $(TBB_CPPFLAGS)                             \
    -I$(top_srcdir)/src/coreapps

switchqos_la_SOURCES =                             \
    switchqos.cc

switchqos_la_LDFLAGS =                             \
    $(AM_LDFLAGS) -module                       \
    -version-info $(SWITCH_LIB_VERSION)

switchqos_la_LIBADD =                              \
    $(TBB_LDFLAGS)                              \
    $(TBB_LIBS)

NOX_RUNTIMEFILES = meta.json

all-local: nox-all-local
clean-local: nox-clean-local 
install-exec-hook: nox-install-local
