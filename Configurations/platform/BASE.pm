package platform::BASE;

use strict;
use warnings;
use Carp;

# Assume someone set @INC right before loading this module
use configdata;

# Globally defined "platform specific" extensions, available for uniformity
sub depext      { '.d' }

# Functions to convert internal file representations to platform specific
# ones.  Note that these all depend on extension functions that MUST be
# defined per platform.
#
# Currently known internal or semi-internal extensions are:
#
# .a            For libraries that are made static only.
#               Internal libraries only.
# .o            For object files.
# .s, .S        Assembler files.  This is an actual extension on Unix
# .res          Resource file.  This is an actual extension on Windows

sub binname     { return $_[1] } # Name of executable binary
sub dsoname     { return $_[1] } # Name of dynamic shared object (DSO)
sub sharedname  { return __isshared($_[1]) ? $_[1] : undef } # Name of shared lib
sub staticname  { return __base($_[1], '.a') } # Name of static lib

# Convenience function to convert the shlib version to an acceptable part
# of a file or directory name.  By default, we consider it acceptable as is.
sub shlib_version_as_filename { return $config{shlib_version} }

# Convenience functions to convert the possible extension of an input file name
sub bin         { return $_[0]->binname($_[1]) . $_[0]->binext() }
sub dso         { return $_[0]->dsoname($_[1]) . $_[0]->dsoext() }
sub sharedlib   { return __concat($_[0]->sharedname($_[1]), $_[0]->shlibext()) }
sub staticlib   { return $_[0]->staticname($_[1]) . $_[0]->libext() }

# More convenience functions for intermediary files
sub def         { return __base($_[1], '.ld') . $_[0]->defext() }
sub obj         { return __base($_[1], '.o') . $_[0]->objext() }
sub res         { return __base($_[1], '.res') . $_[0]->resext() }
sub dep         { return __base($_[1], '.o') . $_[0]->depext() } # <- objname
sub asm         { return __base($_[1], '.S', '.s') . $_[0]->asmext() }

# Another set of convenience functions for standard checks of certain
# internal extensions and conversion from internal to platform specific
# extension.  Note that the latter doesn't deal with libraries because
# of ambivalence
sub isdef       { return $_[1] =~ m|\.ld$|;   }
sub isobj       { return $_[1] =~ m|\.o$|;    }
sub isres       { return $_[1] =~ m|\.res$|;  }
sub isasm       { return $_[1] =~ m|\.[Ss]$|; }
sub convertext {
    if ($_[0]->isdef($_[1]))    { return $_[0]->def($_[1]); }
    if ($_[0]->isobj($_[1]))    { return $_[0]->obj($_[1]); }
    if ($_[0]->isres($_[1]))    { return $_[0]->res($_[1]); }
    if ($_[0]->isasm($_[1]))    { return $_[0]->asm($_[1]); }
    return $_[1];
}

# Install functions ##################################################

# Registered installation paths for different types of files
my %install_paths = ();

sub register_install_path {
    my $self = shift;
    my $path = shift;
    my %opts = @_;

    $install_paths{$opts{type}} = $path;
}

my %install_relocations = (
    misc_script => 'misc',
);

sub get_install_path {
    my $self = shift;
    my $type = my $orig_type = shift;

    while (defined $install_relocations{$type}) {
        $type = $install_relocations{$type};
    }

    croak "No install path defined for $orig_type"
        unless defined $install_paths{$type};

    return $install_paths{$type};
}

#
# Define the needed functions as abstracts
#

# First, the lower level bread and butter functions:

# install_file is used to install any non-executable file
sub install_file {
    croak "platform->install_file not implemented\n";
}

# install_exec is used to install any executable file
sub install_exec {
    croak "platform->install_exec not implemented\n";
}

# install_alias is used to install an alias for another installed file
sub install_alias {
    croak "platform->install_alias not implemented\n";
}

# install_dir is used to install a directory
sub install_dir {
    croak "platform->install_dir not implemented\n";
}

# Now, for the more soffisticated functions.  These differ from the bread
# and buffer functions by massaging the unified "file name" given to them
# to the corresponding platform specific name.

# install_lib is used to install a library
# Apart from converting the unified "file name", it also figures out exactly
# what files there are (both static and shared, in whatever variants they
# come), and where they should go.  This may vary between systems.
#
# This default implementation is the simplest possible, it installs a static
# library in the lib location as a normal file, and the shared library as an
# executable file.
sub install_lib {
    my $self = shift;
    my $libname = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    return platform->install_file(platform->staticlib($libname),
                                  %opts, type => 'lib')
        if $opts{type} eq 'devlib';

    my $shared_lib = platform->sharedlib($libname);
    return platform->install_exec($shared_lib, %opts, type => 'lib')
        if $opts{type} eq 'runtimelib' && $shared_lib;

    croak "No library installer implemented for $opts{type}";
}

sub uninstall_lib {
    my $self = shift;
    my $libname = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    return platform->uninstall_file(platform->staticlib($libname),
                                    %opts, type => 'lib')
        if $opts{type} eq 'devlib';

    my $shared_lib = platform->sharedlib($libname);
    return platform->uninstall_file($shared_lib, %opts, type => 'lib')
        if $opts{type} eq 'runtimelib' && $shared_lib;

    croak "No library uninstaller implemented for $opts{type}";
}

# install_dso is used to install a dynamically loadable module
sub install_dso {
    my $self = shift;
    my $dsoname = shift;

    return platform->install_exec(platform->dso($dsoname), @_);
}

sub uninstall_dso {
    my $self = shift;
    my $dsoname = shift;

    return platform->uninstall_exec(platform->dso($dsoname), @_);
}

# install_bin is used to install a compiled program
# Note that scripts should not be installed with this.  Use install_exec
# directly for those...
sub install_bin {
    my $self = shift;
    my $binname = shift;

    return platform->install_exec(platform->bin($binname), @_);
}

sub uninstall_bin {
    my $self = shift;
    my $binname = shift;

    return platform->uninstall_exec(platform->bin($binname), @_);
}

# Helpers ############################################################

# __base EXPR, LIST
# This returns the given path (EXPR) with the matching suffix from LIST stripped
sub __base {
    my $path = shift;
    foreach (@_) {
        if ($path =~ m|\Q${_}\E$|) {
            return $`;
        }
    }
    return $path;
}

# __isshared EXPR
# EXPR is supposed to be a library name.  This will return true if that library
# can be assumed to be a shared library, otherwise false
sub __isshared {
    return !($disabled{shared} || $_[0] =~ /\.a$/);
}

# __concat LIST
# Returns the concatenation of all elements of LIST if none of them is
# undefined.  If one of them is undefined, returns undef instead.
sub __concat {
    my $result = '';
    foreach (@_) {
        return undef unless defined $_;
        $result .= $_;
    }
    return $result;
}

1;
