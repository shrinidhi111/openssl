package platform::Unix;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::BASE;
@ISA = qw(platform::BASE);

# Assume someone set @INC right before loading this module
use configdata;

sub binext              { $target{exe_extension} || '' }
sub dsoext              { $target{dso_extension} || '.so' }
# Because these are also used in scripts and not just Makefile, we must
# convert $(SHLIB_VERSION_NUMBER) to the actual number.
sub shlibext            { (my $x = $target{shared_extension}
                               || '.so.$(SHLIB_VERSION_NUMBER)')
                              =~ s|\.\$\(SHLIB_VERSION_NUMBER\)
                                  |.$config{shlib_version}|x;
                          $x; }
sub libext              { $target{lib_extension} || '.a' }
sub defext              { $target{def_extension} || '.ld' }
sub objext              { $target{obj_extension} || '.o' }
sub depext              { $target{obj_extension} || '.d' }

# Other extra that aren't defined in platform::BASE
sub shlibextsimple      { (my $x = $target{shared_extension} || '.so')
                              =~ s|\.\$\(SHLIB_VERSION_NUMBER\)||;
                          $x; }
sub shlibvariant        { $target{shlib_variant} || "" }
sub makedepprog         { $disabled{makedepend} ? undef : $config{makedepprog} }

# No conversion of assembler extension on Unix
sub asm {
    return $_[1];
}

# At some point, we might decide that static libraries are called something
# other than the default...
sub staticname {
    # Non-installed libraries are *always* static, and their names remain
    # the same, except for the mandatory extension
    my $in_libname = platform::BASE->staticname($_[1]);
    return $in_libname if $unified_info{attributes}->{$_[1]}->{noinst};

    # We currently return the same name anyway...  but we might choose to
    # append '_static' or '_a' some time in the future.
    return platform::BASE->staticname($_[1]);
}

sub sharedname {
    return platform::BASE::__concat(platform::BASE->sharedname($_[1]),
                                    ($_[0]->shlibvariant() // ''));
}

sub sharedname_simple {
    return platform::BASE::__isshared($_[1]) ? $_[1] : undef;
}

sub sharedlib_simple {
    return platform::BASE::__concat($_[0]->sharedname_simple($_[1]),
                                    $_[0]->shlibextsimple());
}

# Install functions
use File::Spec;

sub _install_file {
    my $srcpath = shift;
    my $dstpath = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    my $before = <<"_____";
${at}\$(ECHO) "install $srcpath -> $dstpath"
${at}cp $srcpath $dstpath.new
_____
    my $after = <<"_____";
${at}chmod 644 $dstpath.new
${at}mv -f $dstpath.new $dstpath
_____

    return
        $before
        .($opts{inject} // sub { '' })->(%opts, file => "$dstpath.new")
        .$after;
}

sub install_file {
    my $self = shift;
    my $srcpath = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    my ($srcvol, $srcdir, $srcfile) = File::Spec->splitpath($srcpath);
    my $dstdir = platform->get_install_path($opts{type});
    my $dstpath = File::Spec->catpath('', $dstdir, $opts{dstfile} // $srcfile);

    if ($opts{type} eq 'conf') {
        (my $cmds1 = _install_file($srcpath, "$dstpath.dist", %opts))
            =~ s/\n$//;
        my $cmds2 = join("\n", map { "\t$_; \\" } split /\n/,
                         _install_file($srcpath, $dstpath, %opts, silent => 0));
        return split /\n/, <<"_____";
$cmds1
${at}if [ ! -f "$dstpath" ]; then \\
$cmds2
fi
_____
    }

    return  split /\n/, _install_file($srcpath, "$dstpath", %opts);
}

sub uninstall_file {
    my $self = shift;
    my $srcpath = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    my ($srcvol, $srcdir, $srcfile) = File::Spec->splitpath($srcpath);
    my $dstdir = platform->get_install_path($opts{type});
    my $dstpath = File::Spec->catpath('', $dstdir, $opts{dstfile} // $srcfile);

    return split /\n/, <<"_____";
${at}\$(ECHO) "\$(RM) $dstpath"
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
${at}\$(ECHO) "install $srcpath -> $dstpath"
${at}cp $srcpath $dstpath.new
${at}chmod 755 $dstpath.new
${at}mv -f $dstpath.new $dstpath
_____
}

sub uninstall_exec {
    goto &uninstall_file;
}

sub install_alias {
    my $self = shift;
    my $alias = shift;
    my $orig = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';
    my $loc = platform->get_install_path($opts{type});

    return split /\n/, <<"_____";
${at}\$(ECHO) "link $loc/$alias -> $loc/$orig"; \
${at}ln -sf $orig $loc/$alias; \
_____
}

sub uninstall_alias {
    my $self = shift;
    my $alias = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    return platform->uninstall_file($alias, %opts);
}

sub install_dir {
    my $self = shift;
    my %opts = @_;

    my $at = $opts{silent} ? '@' : '';
    my $type = {
        $opts{type}     => $opts{type},
        staticlib       => 'lib',
        runtimelib      => 'lib',
        devlib          => 'lib',
    } -> {$opts{type}};
    my $dir = platform->get_install_path($type);

    return split /\n/, <<"_____";
${at}\$(PERL) \$(SRCDIR)/util/mkdir-p.pl $dir
_____
}

sub uninstall_dir {
    my $self = shift;
    my %opts = @_;

    my $at = $opts{silent} ? '@' : '';
    my $type = {
        $opts{type}     => $opts{type},
        runtimelib      => 'lib',
        devlib          => 'lib',
    } -> {$opts{type}};
    my $dir = platform->get_install_path($type);

    return split /\n/, <<"_____";
-${at}\$(RMDIR) $dir
_____
}

# This one is "magical" mostly because there is a lot of variety
sub install_lib {
    my $self = shift;
    my $libname = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    if ($opts{type} eq 'devlib') {
        my $shared_lib = platform->sharedlib($libname);
        my $shared_lib_simple = platform->sharedlib_simple($libname);

        # Install a static library as a normal file, but with an injected
        # $(RANLIB) command.
        my @cmds = platform->install_file(platform->staticlib($libname),
                                          %opts, type => 'lib',
                                          inject => sub {
                                              my %opts = @_;
                                              my $at = $opts{silent} ? '@' : '';

                                              return <<"_____"
${at}\$(RANLIB) $opts{file}
_____
                                          });
        # Install a simple shared library unless it's the same file as the
        # main shared library, which is installed as a runtimelib.  The simple
        # shared library is usually an alias that allows -lcrypto for a more
        # complex main shared library name.
        push @cmds, platform->install_alias($shared_lib_simple, $shared_lib,
                                            %opts, type => 'lib')
            if $shared_lib && $shared_lib ne $shared_lib_simple;

        return @cmds;
    }

    return platform->SUPER::install_lib($libname, %opts);
}

sub uninstall_lib {
    my $self = shift;
    my $libname = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    my $static_lib = platform->staticlib($libname);
    my $shared_lib = platform->sharedlib($libname);
    my $shared_lib_simple = platform->sharedlib_simple($libname);

    return ( platform->uninstall_file($static_lib, %opts, type => 'lib'),
             ($shared_lib && $shared_lib ne $shared_lib_simple
                  ? platform->uninstall_file($shared_lib_simple, %opts,
                                             type => 'lib')
                  : ()) )
        if $opts{type} eq 'devlib';

    return platform->SUPER::uninstall_lib($libname, %opts);
}

1;
