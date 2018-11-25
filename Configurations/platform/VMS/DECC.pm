package platform::VMS::DECC;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::VMS;
@ISA = qw(platform::VMS);

# Assume someone set @INC right before loading this module
use configdata;

# Helper function to deal with inclusion directory specs.
# We have to deal with two things:
# 1. comma separation and no possibility of trailing comma
# 2. no inclusion directories given at all
# 3. long compiler command lines
# To resolve 1, we need to iterate through the sources of inclusion
# directories, and only add a comma when needed.
# To resolve 2, we need to have a variable that will hold the whole
# inclusion qualifier, or be the empty string if there are no inclusion
# directories.  That's the symbol 'qual_includes' that's used in CPPFLAGS
# To resolve 3, we creata a logical name TMP_INCLUDES: to hold the list
# of inclusion directories.
#
# This function returns a list of two lists, one being the collection of
# commands to execute before the compiler is called, and the other being
# the collection of commands to execute after.  It takes as arguments the
# collection of strings to include as directory specs.
sub _includes {
    my @stuff = ( @_ );
    my @before = ( '@ qual_includes :=' );
    my @after = ( '@ DELETE/SYMBOL/LOCAL qual_includes' );

    if (scalar @stuff > 0) {
        my $stuff = shift(@stuff);
        push @before, ( (split /\n/, <<"_____"),
\@ tmp_includes := $stuff
_____
                        (map { $stuff = $_; split /\n/, <<"_____" } @stuff),
\@ tmp_add := $stuff
\@ IF tmp_includes .NES. "" .AND. tmp_add .NES. "" THEN -
	tmp_includes = tmp_includes + ","
\@ tmp_includes = tmp_includes + tmp_add
_____
                        (split /\n/, <<"_____") );
\@ IF tmp_includes .NES. "" THEN DEFINE tmp_includes 'tmp_includes'
\@ IF tmp_includes .NES. "" THEN qual_includes := /INCLUDE=(tmp_includes:)
\@ DELETE/SYMBOL/LOCAL tmp_includes
\@ DELETE/SYMBOL/LOCAL tmp_add
_____

        push @after, (split /\n/, <<"_____");
\@ DEASSIGN tmp_includes:
_____
    }
    return ([ @before ], [ @after ]);
}

sub preprocess {
    my $self = shift;
    my $target = shift;
    my %opts = @_;

    my $cppflags = {
        shlib => '$(LIB_CFLAGS) $(LIB_CPPFLAGS)',
        lib => '$(LIB_CFLAGS) $(LIB_CPPFLAGS)',
        dso => '$(DSO_CFLAGS) $(DSO_CPPFLAGS)',
        bin => '$(BIN_CFLAGS) $(BIN_CPPFLAGS)'
       } -> {$opts{intent}};
    my @incs_cmds = _includes({ shlib => '$(LIB_INCLUDES)',
                                lib => '$(LIB_INCLUDES)',
                                dso => '$(DSO_INCLUDES)',
                                bin => '$(BIN_INCLUDES)' } -> {$opts{intent}},
                              '$(CNF_INCLUDES)',
                              '$(INCLUDES)',
                              @{$opts{incs}});
    my $incs_on = join("\n", @{$incs_cmds[0]}) || '!';
    my $incs_off = join("\n", @{$incs_cmds[1]}) || '!';
    my $defs = join("", map { ",".$_ } @{$opts{defs}});

    my @cmds = ( (split /\n/, <<"_____"),
$incs_on
\@ extradefines = "$defs"
PIPE \$(CPP) $cppflags $opts{src} | -
_____
                 ($opts{clean} ? split /\n/, <<"_____" : ()),
\$(PERL) -ne "/^#(\\s*line)?\\s*[0-9]+\\s+""/ or print" > $target-i
_____
                 (split /\n/, <<"_____") );
\@ DELETE/SYMBOL/LOCAL extradefines
$incs_off
RENAME $target-i $target
_____
    return ( target => $target,
             deps => [ $opts{src} ],
             cmds => [ @cmds ] );
}

sub compile_C {
    my $self = shift;
    my $target = platform->obj(shift);
    my %opts = @_;

    # Because VMS C isn't very good at combining a /INCLUDE path with
    # #includes having a relative directory (like '#include "../foo.h"),
    # the best choice is to move to the first source file's intended
    # directory before compiling, and make sure to write the object file
    # in the correct position (important when the object tree is other
    # than the source tree).
    my $forward = dirname($opts{srcs}->[0]);
    my $backward = abs2rel(rel2abs("."), rel2abs($forward));
    my $targetd = abs2rel(rel2abs(dirname($target)), rel2abs($forward));
    my $targetn = basename($target);

    my @srcs = map { platform->convertext($_) } @{$opts{srcs}};

    my $cflags;
    if ($opts{installed}) {
        $cflags = { shlib => '$(LIB_CFLAGS)',
                    lib   => '$(LIB_CFLAGS)',
                    dso   => '$(DSO_CFLAGS)',
                    bin   => '$(BIN_CFLAGS)' } -> {$opts{intent}};
    } else {
        $cflags = { shlib => '$(NO_INST_LIB_CFLAGS)',
                    lib   => '$(NO_INST_LIB_CFLAGS)',
                    dso   => '$(NO_INST_DSO_CFLAGS)',
                    bin   => '$(NO_INST_BIN_CFLAGS)' } -> {$opts{intent}};
    }
    $cflags .= { shlib => '$(LIB_CPPFLAGS)',
                 lib   => '$(LIB_CPPFLAGS)',
                 dso   => '$(DSO_CPPFLAGS)',
                 bin   => '$(BIN_CPPFLAGS)' } -> {$opts{intent}};
    my $defs = join("", map { ",".$_ } @{$opts{defs}});

    my @incs_cmds =
        platform->_includes({ shlib => '$(LIB_INCLUDES)',
                              lib   => '$(LIB_INCLUDES)',
                              dso   => '$(DSO_INCLUDES)',
                              bin   => '$(BIN_INCLUDES)' } -> {$opts{intent}},
                            '$(INCLUDES)',
                            map {
                                file_name_is_absolute($_)
                                    ? $_ : catdir($backward,$_)
                                } @{$opts{incs}});
    my $incs_on = join("\n\t", @{$incs_cmds[0]}) || '!';
    my $incs_off = join("\n\t", @{$incs_cmds[1]}) || '!';
    my $depbuild = $disabled{makedepend}
        ? "" : " /MMS=(FILE=${objd}${objn}.D,TARGET=$obj)";

    return ( target => $target,
             deps => [ @srcs, @{$opts{deps}} ],
             cmds => [ split /\n/, <<"_____" ] );
SET DEFAULT $forward
$incs_on
\@ extradefines = "$defs"
\$(CC) $cflags$depbuild /OBJECT=$objd$objn /REPOSITORY=$backward $srcs
\@ DELETE/SYMBOL/LOCAL extradefines
$incs_off
SET DEFAULT $backward
- PURGE $target
_____
}

# This is fairly unique for VMS...  symbols are historically limited to
# 31 characters.  With DEC C, /NAMES=SHORTENED can be used to shorten
# names that are longer than that, and a dictionary is built up in the
# file CXX$DEMANGLER_DB.  We use a script to use this database to
# translate any export .OPT file.
sub translate_export {
    my $self = shift;
    my $target = shift;
    my %opts = @_;

    my $translatesyms_pl = abs2rel(rel2abs(catfile($config{sourcedir},
                                                   "VMS", "translatesyms.pl")),
                                   rel2abs($config{builddir}));

    return ( target => "$target-translated",
             cmds   => [ split /\n/, <<"_____" ] );
\$(PERL) $translatesyms_pl \$(BLDDIR)CXX\$DEMANGLER_DB. < $target > $target-translated
_____
}

1;
