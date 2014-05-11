## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include $(PTHREAD_CFLAGS) @CLIBFLAGS@
SUBDIRS = include src $(TESTS_SUBDIR)
ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA = AUTHORS CHANGES COPYING INSTALL README

if MAINTAINER_MODE
INSTALL_MAINTAINER_CLEAN=INSTALL INSTALL.pdf
endif

if TESTS
TESTS_SUBDIR = tests
endif

test:
if TEST_SCRIPTS
	cd tests && $(MAKE) test
else
	@echo Not built
endif

clean-local:
	rm -f INSTALL.htm* INSTALL.4ct INSTALL.4tc INSTALL.css INSTALL.idv INSTALL.lg
	rm -f INSTALL.aux INSTALL.dvi INSTALL.log INSTALL.out INSTALL.toc INSTALL.tmp
	rm -f INSTALL.xref $(INSTALL_MAINTAINER_CLEAN)
	rm -f *~

# make INSTALL depend on INSTALL.pdf to avoid tmp-file conflict when two tex-scripts are running
INSTALL: INSTALL.tex INSTALL.htex INSTALL.pdf
	htlatex INSTALL.htex "html,1,info"
	sed -e 's/&#8221\;/\&quot\;/g' -e "s/\&#8217\;/'/g" -e "s/\&hellip\;/.../g" <INSTALL.html >INSTALL.htm
	w3m -O iso-8859-1 -dump INSTALL.htm >INSTALL

INSTALL.pdf: INSTALL.tex INSTALL.ptex
	pdflatex INSTALL.ptex
	pdflatex INSTALL.ptex
	pdflatex INSTALL.ptex

#test:
#	cd src && $(MAKE) test
