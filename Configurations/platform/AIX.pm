package platform::AIX;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::Unix;
@ISA = qw(platform::Unix);

# Assume someone set @INC right before loading this module
use configdata;

# Shared AIX support is special. We put libcrypto[64].so.ver into
# libcrypto.a and use libcrypto_a.a as static one.
sub libext              { '_a.a' }
sub shlibextsimple      { '.a' }

# In shared mode, the default static library names clashes with the final
# "simple" full shared library name, so we add '_a' to the basename of the
# static libraries in that case.
sub staticname {
    # Non-installed libraries are *always* static, and their names remain
    # the same, except for the mandatory extension
    my $in_libname = platform::BASE->staticname($_[1]);
    return $in_libname if $unified_info{attributes}->{$_[1]}->{noinst};

    return platform::BASE->staticname($_[1]) . '_a';

# Shared libraries are different on AIX
sub install_lib {
    my $self = shift;
    my $libname = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    my $dstdir = platform->get_install_path('lib');
    my $shared_lib = platform->sharedlib($libname);
    my $shared_lib_simple = platform->sharedlib_simple($libname);

    return split /\n/, <<"_____" if $opts{type} eq 'runtimelib' && $shared_lib;
${at}\$(ECHO) "install $shared_lib -> $dstdir/$shared_lib_simple"
${at}if [ -f $dstdir/$shared_lib_simple ]; then \\
	(
		trap "rm -rf /tmp/ar.\$\$\$\$" INT 0; \\
		mkdir /tmp/ar.\$\$\$\$; \\
		(
			cd /tmp/ar.\$\$\$\$; \\
			cp -f $dstdir/$shared_lib_simple $dstdir/$shared_lib_simple.new; \\
			for so in `\$(AR) t $dstdir/$shared_lib_simple`; do \\
				\$(AR) x $dstdir/$shared_lib_simple \$\$so; \\
				chmod u+w \$\$so; \\
				strip -X32_64 -e \$\$so; \\
				\$(AR) r $dstdir/$shared_lib_simple.new \$\$so; \\
			done; \\
		) \\
	); \\
fi; \\
${at}\$(AR) r $dstdir/$shared_lib_simple.new $shared_lib; \\
${at}mv -f $dstdir/$shared_lib_simple.new $dstdir/$shared_lib_simple
_____

    return platform->SUPER::install_lib($libname, %opts);
}
