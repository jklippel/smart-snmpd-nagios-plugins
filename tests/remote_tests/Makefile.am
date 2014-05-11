## Process this file with automake to produce Makefile.in

noinst_PROGRAMS = $(test_script)
noinst_DATA = remote_test.cfg

EXTRA_DIST = remote_test.cfg.in

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir)\
	      -I$(top_srcdir)/src -I$(top_builddir)/src\
	      -I$(top_srcdir)/tests/testlib \
	       @CLIBFLAGS@

if TEST_SCRIPTS
script_edit=	$(PERL5) $(srcdir)/../testlib/mk_run_tests.pl \
		-d test-name=remote_test \
		-d test-dir="$(subdir)" \
		-d top_builddir="$(top_builddir)"

test_script = run_tests.t

run_tests_t_SOURCES = $(srcdir)/../testlib/run_tests.pl.in

run_tests.t: Makefile $(srcdir)/../testlib/mk_run_tests.pl $(srcdir)/../testlib/run_tests.t.in
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ../testlib/$@.in || srcdir=$(srcdir)/; \
	  $(script_edit) -i $${srcdir}../testlib/$@.in >$@.tmp
	chmod +rx $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

remote_test.cfg: Makefile $(srcdir)/../testlib/mk_run_tests.pl $(srcdir)/remote_test.cfg.in
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f $@.in || srcdir=$(srcdir)/; \
	  $(script_edit) -i $${srcdir}$@.in >$@.tmp
	chmod +rx $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

if CFG_DIR
cfg_param = :: -d $(CFG_DIR)
endif

test: $(noinst_PROGRAMS) remote_test.cfg
	$(PERL5) -MApp::Prove -e 'my $$app = App::Prove->new(); $$app->process_args(@ARGV); exit( $$app->run ? 0 : 1 );' . $(cfg_param)
endif
