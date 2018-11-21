package platform::VMS;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::BASE;
@ISA = qw(platform::BASE);

# Assume someone set @INC right before loading this module
use configdata;

# VMS has a cultural standard where all installed libraries are prefixed.
# For OpenSSL, the choice is 'ossl$' (this prefix was claimed in a
# conversation with VSI, Tuesday January 26 2016)
sub osslprefix          { 'OSSL$' }

sub binext              { '.EXE' }
sub dsoext              { '.EXE' }
sub shlibext            { '.EXE' }
sub libext              { '.OLB' }
sub defext              { '.OPT' }
sub objext              { '.OBJ' }
sub depext              { '.D' }
sub asmext              { '.ASM' }

# Other extra that aren't defined in platform::BASE
sub shlibvariant        { $target{shlib_variant} || '' }

sub optext              { '.OPT' }
sub optname             { return $_[1] }
sub opt                 { return $_[0]->optname($_[1]) . $_[0]->optext() }

# Other projects include the pointer size in the name of installed libraries,
# so we do too.
sub staticname {
    # Non-installed libraries are *always* static, and their names remain
    # the same, except for the mandatory extension
    my $in_libname = platform::BASE->staticname($_[1]);
    return $in_libname if $unified_info{attributes}->{$_[1]}->{noinst};

    return platform::BASE::__concat($_[0]->osslprefix(),
                                    platform::BASE->staticname($_[1]),
                                    $target{pointer_size});
}

# To enable installation of multiple major OpenSSL releases, we include the
# version number in installed shared library names.
my $sover_filename =
    join('', map { sprintf "%02d", $_ } split(m|\.|, $config{shlib_version}));
sub shlib_version_as_filename {
    return $sover_filename;
}
sub sharedname {
    return platform::BASE::__concat($_[0]->osslprefix(),
                                    platform::BASE->sharedname($_[1]),
                                    $_[0]->shlib_version_as_filename(),
                                    ($_[0]->shlibvariant() // ''),
                                    "_shr$target{pointer_size}");
}

sub _install_file {
    my $srcpath = shift;
    my $dstpath = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@ ' : '';

    return <<"_____";
${at}COPY/PROT=W:R $srcpath $dstpath
_____
}

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
${at}IF F\$SEARCH("$dstpath") .EQS. "" THEN -
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
    my $dstpath = File::Spec->catdir($dstdir, $opts{dstfile} // $srcfile).';*';

    return split /\n/, <<"_____";
${at}\$(RM) $dstpath
_____
}

sub install_exec {
    my $self = shift;
    my $srcpath = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    my ($srcvol, $srcdir, $srcfile) = File::Spec->splitpath($srcpath);
    my $dstdir = platform->get_install_path($opts{type});
    my $dstpath = File::Spec->catpath('', $dstdir, $opts{dstfile} // $srcfile);

    return split /\n/, <<"_____";
${at}COPY/PROT=W:RE $srcpath $dstpath
_____
}

sub uninstall_exec {
    goto &uninstall_file;
}

use File::Basename;

use if $^O eq 'VMS', 'VMS::Filespec' ; # To get fileify()
# to simulate fileify, which becomes an identity functions on other OSes
*fileify = sub { $_[0]; } unless $^O eq 'VMS';

sub install_dir {
    my $self = shift;
    my %opts = @_;

    my $at = $opts{silent} ? '@ ' : '';
    my $type = {
        $opts{type}     => $opts{type},
        runtimelib      => 'lib',
        devlib          => 'lib',
    } -> {$opts{type}};
    my $dir = platform->get_install_path($type);
    my $dirfile = fileify($dir);
    my $permission = {
        !1              => 'S:RWED,O:RWE,G:RE,W:RE',
        !!1             => 'S:RWED,O:RWE,G,W',
    } -> {!!$opts{private}};

    return split /\n/, <<"_____"
${at}IF F\$SEARCH("$dirfile") .EQS. "" THEN -
        CREATE/DIR/PROT=($permission) $dir
_____
}

sub uninstall_dir {
    my $self = shift;
    my %opts = @_;

    my $at = $opts{silent} ? '@ ' : '';
    my $type = {
        $opts{type}     => $opts{type},
        runtimelib      => 'lib',
        devlib          => 'lib',
    } -> {$opts{type}};
    my $dir = platform->get_install_path($type);
    my $dirfile = fileify($dir);

    return split /\n/, <<"_____";
-${at}DELETE $dirfile
_____
}

1;
