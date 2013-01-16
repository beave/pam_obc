UTOMAKE_OPIONS=foreign no-dependencies
SUBDIRS = src

INCLUDES = @INCLUDES@

# Install BFD include file, and others that it needs.
#install-data-local: 
#       @$(NORMAL_INSTALL)
#       $(mkinstalldirs) $(sysconfdir)
#       $(INSTALL_DATA)sagan.conf $(sysconfdir)/sagan.conf

install-data-local:

	$(INSTALL) -m 644 src/pam_obc /lib/security/pam_obc.so
	test -e /etc/pam_obc.conf || $(INSTALL) -m 600 etc/pam_obc.conf /etc/pam_obc.conf

	@echo "------------------------------------------------------------------------------"
	@echo "\"pam_obc\" has been installed!"
	@echo "------------------------------------------------------------------------------"

