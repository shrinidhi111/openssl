package platform;

use strict;
use warnings;
use vars qw(@ISA);

# Callers must make sure @INC has the build directory
use configdata;

my @modules = @{$target{perl_platform}} || ( 'Unix' );
foreach (@modules) {
    (my $module_path = $_) =~ s|::|/|g;
    require "platform/$module_path.pm";
}
@ISA = map { "platform::$_" } @modules;

1;

__END__
