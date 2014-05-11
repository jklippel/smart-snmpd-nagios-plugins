# Makefile for libstatgrab/docs
# http://www.i-scream.org/libstatgrab/
# $Id: Makefile.am,v 1.28 2005/04/25 12:37:20 tdb Exp $

SUBDIRS = testlib $(tests_dirs)

tests_dirs = local_tests remote_tests smooth_tests snmpd_tests

if TEST_SCRIPTS
if CFG_DIR
cfg_param = :: -d $(CFG_DIR)
endif

test:
	$(PERL5) -MApp::Prove -e 'my $$app = App::Prove->new(); $$app->process_args(@ARGV); exit( $$app->run ? 0 : 1 );' $(tests_dirs) $(cfg_param)
endif
