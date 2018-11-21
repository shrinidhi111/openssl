package platform::Windows;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::BASE;
@ISA = qw(platform::BASE);

# Assume someone set @INC right before loading this module
use configdata;

sub binext              { '.exe' }
sub dsoext              { '.dll' }
sub shlibext            { '.dll' }
sub libext              { '.lib' }
sub defext              { '.def' }
sub objext              { '.obj' }
sub depext              { '.d' }
sub asmext              { '.asm' }

# Other extra that aren't defined in platform::BASE
sub resext              { '.res' }
sub shlibextimport      { '.lib' }
sub shlibvariant        { $target{shlib_variant} || '' }

sub staticname {
    # Non-installed libraries are *always* static, and their names remain
    # the same, except for the mandatory extension
    my $in_libname = platform::BASE->staticname($_[1]);
    return $in_libname if $unified_info{attributes}->{$_[1]}->{noinst};

    # To make sure not to clash with an import library, we make the static
    # variant of our installed libraries get '_static' added to their names.
    return platform::BASE->staticname($_[1])
        . ($disabled{shared} ? '' : '_static');
}

# To mark forward compatibility, we include the OpenSSL major release version
# number in the installed shared library names.
(my $sover_filename = $config{shlib_version}) =~ s|\.|_|g;
sub shlib_version_as_filename {
    return $sover_filename
}
sub sharedname {
    return platform::BASE::__concat(platform::BASE->sharedname($_[1]),
                                    "-",
                                    $_[0]->shlib_version_as_filename(),
                                    ($_[0]->shlibvariant() // ''));
}

sub sharedname_import {
    return platform::BASE::__isshared($_[1]) ? $_[1] : undef;
}

sub sharedlib_import {
    return platform::BASE::__concat($_[0]->sharedname_import($_[1]),
                                    $_[0]->shlibextimport());
}

sub _install_file {
    my $srcpath = shift;
    my $dstpath = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@ ' : '';
    my $copyargs = $opts{copyargs} // '';

    return <<"_____";
${at}\$(ECHO) "install $srcpath -> $dstpath"
${at}"\$(PERL)" "\$(SRCDIR)\\util\\copy.pl" $copyargs "$srcpath" "$dstpath"
_____
}

use File::Basename;

sub install_file {
    my $self = shift;
    my $srcpath = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@ ' : '';

    my $srcfile = basename($srcpath);
    my $dstdir = platform->get_install_path($opts{type});
    my $dstpath = File::Spec->catfile($dstdir, $opts{dstfile} // $srcfile);

    if ($opts{type} eq 'conf') {
        (my $cmds1 = _install_file($srcpath, "$dstpath-dist", %opts))
            =~ s/\n$//;
        my $cmds2 = join("\n", map { "\t$_; \\" } split /\n/,
                         _install_file($srcpath, $dstpath, %opts, silent => 0));
        return split /\n/, <<"_____";
$cmds1
${at}IF NOT EXIST "$dstpath" THEN \\
$cmds2
fi
_____
    }

    return  split /\n/, _install_file($srcpath, $dstpath, %opts);
}

sub uninstall_file {
    my $self = shift;
    my $srcpath = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@ ' : '';

    my $srcfile = basename($srcpath);
    my $dstdir = platform->get_install_path($opts{type});
    my $dstpath = File::Spec->catdir($dstdir, $opts{dstfile} // $srcfile);

    return split /\n/, <<"_____";
${at}\$(ECHO) "\$(RM) $dstpath"
${at}\$(RM) $dstpath
_____
}

sub install_exec {
    goto &install_file;
}

sub uninstall_exec {
    goto &install_file;
}

sub install_dir {
    my $self = shift;
    my %opts = @_;

    my $at = $opts{silent} ? '@ ' : '';
    my $type = {
        $opts{type}     => $opts{type},
        runtimelib      => 'bin',
        devlib          => 'lib',
    } -> {$opts{type}};
    my $dir = platform->get_install_path($type);

    return split /\n/, <<"_____"
${at}"\$(PERL)" "\$(SRCDIR)\\util\\mkdir-p.pl" "$dir"
_____
}

sub uninstall_dir {
    my $self = shift;
    my %opts = @_;

    my $at = $opts{silent} ? '@ ' : '';
    my $type = {
        $opts{type}     => $opts{type},
        runtimelib      => 'bin',
        devlib          => 'lib',
    } -> {$opts{type}};
    my $dir = platform->get_install_path($type);

    return split /\n/, <<"_____";
-${at}\$(RMDIR) "$dir"
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
            platform->install_file(platform->sharedlib_import($libname),
                                   %opts, type => 'lib')
            if $shared_lib;

        return @cmds;
    }

    return platform->install_exec($shared_lib, %opts, type => 'bin')
        if $opts{type} eq 'runtimelib' && $shared_lib;

    return platform->SUPER::install_lib($libname, %opts);
}

1;
