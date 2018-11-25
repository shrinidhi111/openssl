package platform::VMS::ias;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::VMS;
@ISA = qw(platform::VMS);

# Assume someone set @INC right before loading this module
use configdata;

sub compile_asm {
    my $self = shift;
    my $target = platform->obj(shift);
    my %opts = @_;

    my @srcs = map { platform->convertext($_) } @{$opts{srcs}};

    my $flags = { shlib => '$(LIB_ASFLAGS)',
                  lib   => '$(LIB_ASFLAGS)',
                  dso   => '$(DSO_ASFLAGS)',
                  bin   => '$(BIN_ASFLAGS)' } -> {$opts{intent}};
    return ( target => $target,
             deps => [ @srcs, @{$opts{deps}} ],
             cmds => [ split /\n/, <<"_____" ] );
\$(AS) $flags \$(ASOUTFLAG)$target $srcs
_____
}

1;
