package platform::mingw;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::Unix;
@ISA = qw(platform::Unix);

# Assume someone set @INC right before loading this module
use configdata;

sub binext              { '.exe' }
sub objext              { '.obj' }
sub libext              { '.a' }
sub dsoext              { '.dll' }
sub defext              { '.def' }
sub shlibext            { '.dll' }
sub shlibextimport      { $target{shared_import_extension} || '.dll.a' }
sub shlibextsimple      { undef }
sub makedepprog         { $disabled{makedepend} ? undef : $config{makedepprog} }

(my $sover_filename = $config{shlib_version}) =~ s|\.|_|g;
sub shlib_version_as_filename {
    return $sover_filename;
}
sub sharedname {
    return platform::BASE::__concat(platform::BASE->sharedname($_[1]),
                                    "-",
                                    $_[0]->shlib_version_as_filename(),
                                    ($config{target} eq "mingw64"
                                         ? "-x64" : ""));
}

# With Mingw and other DLL producers, there isn't really any "simpler"
# shared library name.  However, there is a static import library, so
# we return that instead.
sub sharedlib_simple {
    return platform::BASE::__concat(platform::BASE->sharedname($_[1]),
                                    $_[0]->shlibextimport());
}

# Because Mingw is really Windows, we don't have symbolic links,
# so we copy instead.
sub install_alias {
    my $self = shift;
    my $alias = shift;
    my $orig = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';
    my $loc = platform->get_install_path($opts{type});

    return split /\n/, <<"_____";
${at}\$(ECHO) "copy $loc/$orig -> $loc/$alias"
${at}cp $loc/$orig $loc/$alias
_____
}

# Shared libraries are different on Windows
sub install_lib {
    my $self = shift;
    my $libname = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    my $shared_lib = platform->sharedlib($libname);

    if ($opts{type} eq 'devlib') {
        # Install a static library as a normal file
        my @cmds = platform->install_file(platform->staticlib($libname),
                                          %opts, type => 'lib');

        # Also install the import library as a normal file
        push @cmds,
            platform->install_file(platform->sharedlib_simple($libname),
                                   %opts, type => 'lib')
            if $shared_lib;

        return @cmds;
    }

    return platform->install_exec($shared_lib, %opts, type => 'bin')
        if $opts{type} eq 'runtimelib' && $shared_lib;

    return platform->SUPER::install_lib($libname, %opts);
}

sub install_dir {
    my $self = shift;
    my %opts = @_;

    $opts{type} = {
        $opts{type}     => $opts{type},
        runtimelib      => 'bin',
    } -> {$opts{type}};
    return platform->SUPER::install_dir(%opts);
}

1;
