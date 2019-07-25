<<<<<<< HEAD
bin_PROGRAMS += controller-vtep/ovn-controller-vtep
controller_vtep_ovn_controller_vtep_SOURCES = \
	controller-vtep/binding.c \
	controller-vtep/binding.h \
	controller-vtep/gateway.c \
	controller-vtep/gateway.h \
	controller-vtep/ovn-controller-vtep.c \
	controller-vtep/ovn-controller-vtep.h \
	controller-vtep/vtep.c \
	controller-vtep/vtep.h
controller_vtep_ovn_controller_vtep_LDADD = lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la ovs/vtep/libvtep.la
man_MANS += controller-vtep/ovn-controller-vtep.8
EXTRA_DIST += controller-vtep/ovn-controller-vtep.8.xml
CLEANFILES += controller-vtep/ovn-controller-vtep.8
=======
bin_PROGRAMS += ovn/controller-vtep/ovn-controller-vtep
ovn_controller_vtep_ovn_controller_vtep_SOURCES = \
	ovn/controller-vtep/binding.c \
	ovn/controller-vtep/binding.h \
	ovn/controller-vtep/gateway.c \
	ovn/controller-vtep/gateway.h \
	ovn/controller-vtep/ovn-controller-vtep.c \
	ovn/controller-vtep/ovn-controller-vtep.h \
	ovn/controller-vtep/vtep.c \
	ovn/controller-vtep/vtep.h
ovn_controller_vtep_ovn_controller_vtep_LDADD = ovn/lib/libovn.la lib/libopenvswitch.la vtep/libvtep.la
man_MANS += ovn/controller-vtep/ovn-controller-vtep.8
EXTRA_DIST += ovn/controller-vtep/ovn-controller-vtep.8.xml
CLEANFILES += ovn/controller-vtep/ovn-controller-vtep.8
>>>>>>> 963245950b871dc564dfb38e48de44284f5cf88e
