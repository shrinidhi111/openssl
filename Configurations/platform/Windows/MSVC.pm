package platform::Windows::MSVC;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::Windows;
@ISA = qw(platform::Windows);

# Assume someone set @INC right before loading this module
use configdata;

sub pdbext              { '.pdb' }

sub staticlibpdb {
    return platform::BASE::__concat($_[0]->staticname($_[1]), $_[0]->pdbext());
}

sub sharedlibpdb {
    return platform::BASE::__concat($_[0]->sharedname($_[1]), $_[0]->pdbext());
}

sub dsopdb {
    return platform::BASE::__concat($_[0]->dsoname($_[1]), $_[0]->pdbext());
}

sub binpdb {
    return platform::BASE::__concat($_[0]->binname($_[1]), $_[0]->pdbext());
}

sub install_lib {
    my $self = shift;
    my $libname = shift;
    my %opts = @_;
    my $at = $opts{silent} ? '@' : '';

    my $shared_lib = platform->sharedlib($libname);
    my @extra = ();

    push @extra,
        platform->install_file(platform->staticlibpdb($libname).
                               %opts, type => 'lib')
        if $opts{type} eq 'devlib' && !$shared_lib;

    push @extra,
        platform->install_exec(platform->sharedlibpdb($libname),
                                    %opts, type => 'bin')
        if $opts{type} eq 'runtimelib' && $shared_lib;

    return ( platform->SUPER::install_lib($libname, %opts),
             @extra );
}

sub install_dso {
    my $self = shift;
    my $dsoname = shift;

    return ( platform->SUPER::install_dso($dsoname, @_),
             platform->install_file(platform->dsopdb($dsoname), @_) );
}

sub uninstall_dso {
    my $self = shift;
    my $dsoname = shift;

    return ( platform->SUPER::uninstall_dso($dsoname, @_),
             platform->uninstall_file(platform->dsopdb($dsoname), @_) );
}

sub install_bin {
    my $self = shift;
    my $binname = shift;

    return ( platform->SUPER::install_bin($binname, @_),
             platform->install_file(platform->binpdb($binname), @_) );
}

sub uninstall_bin {
    my $self = shift;
    my $binname = shift;

    return ( platform->SUPER::uninstall_bin($binname, @_),
             platform->uninstall_file(platform->binpdb($binname), @_) );
}

1;
