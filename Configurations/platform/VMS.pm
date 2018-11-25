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
    return $in_libname
        unless ( grep { platform::BASE->staticname($_) eq $in_libname }
                 @{$unified_info{install}->{libraries}} );

    return platform::BASE::__concat($_[0]->osslprefix(),
                                    platform::BASE->staticname($_[1]),
                                    $target{pointer_size});
}

# To enable installation of multiple major OpenSSL releases, we include the
# version number in installed shared library names.
my $sover_filename =
    sprintf "%02d%02d", split m|\.|, $config{shlib_version_number};
sub sharedname {
    return platform::BASE::__concat($_[0]->osslprefix(),
                                    platform::BASE->sharedname($_[1]),
                                    "$sover_filename",
                                    ($_[0]->shlibvariant() // ''),
                                    "_shr$target{pointer_size}");
}

use File::Spec::Functions;
sub generate_export {
    my $self = shift;
    my $target = platform->def(shift);
    my %opts = @_;

    my $mkdef = catfile($config{sourcedir}, 'util', 'mkdef.pl');
    my $version = $opts{version} ? " --version $opts{version}" : '';
    my $case_insensitive = $opts{case_insensitive} ? ' --case-insensitive' : '';
    return ( target => $target,
             deps => [ $opts{ordinals}, $mkdef ],
             cmds => [ split /\n/, <<"_____" ] );
\$(PERL) $mkdef$version --ordinals $opts{ordinals} --name $opts{name} "--OS" "VMS"$case_insensitive > $target
_____
}

sub generate_asm {
    my $self = shift;
    my $target = shift;
    my %opts = @_;

    my %data = ();

    # If the generator is a perl script, it's used to produce an assembler
    # file.  If the target file is .S internally (capital S), then this file
    # is intermediary, and is sent through the C preprocessor, the result of
    # which becomes the final assembler file.
    # Finally, if the generator is a .S file, it's also sent through the C
    # preprocessor, the result of which becomes the final assembler file.
    my $use_cpp = 0;
    my $is_S = $target =~ m|\.S$|;

    print STDERR "DEBUG[generate_asm]: (1) target = $target\n";
    print STDERR "DEBUG[generate_asm]: is S = $is_S\n";
    print STDERR "DEBUG[generate_asm]: generator = ",
        join(' ', @{$opts{generator}}), "\n";

    $target = platform->asm($target);

    print STDERR "DEBUG[generate_asm]: (2) target = $target\n";

    if ($opts{generator}->[0] =~ m|\.pl$|) {
        my $generator = join(' ', @{$opts{generator}});
        my $generator_incs =
            join('', map { ' "-I'.$_.'"' } @{$opts{generator_incs}});

        if ($is_S) {
            $use_cpp = 1;
            # Generate the final assembler in two steps
            %data = ( target => "$target-S", # Intermediary file name
                      cleanup => [ split /\n/, <<"_____" ] );
DELETE $target-S;*
_____
        } else {
            %data = ( target => $target ); # Final file name
        }

        $data{deps} = [ $opts{generator}->[0] ];
        $data{cmds} = [ split /\n/, <<"_____" ];
\$(PERL)$generator_incs $generator $data{target}
_____
    } elsif ($opts{generator}->[0] =~ m|\.S$|) {
        $use_cpp = 1;
    } else {
        croak "Generator type for $target unknown: ",
            join(' ', @{$opts{generator}}),
            "\n";
    }

    print STDERR "DEBUG[generate_asm]: (1) \%data:\n  ",
        join("\n  ", map { $_.' => '.(ref $data{$_} eq ''
                                      ? $data{$_}
                                      : '[ '.join("\n".' ' x (length($_) + 8),
                                                  @{$data{$_}}).' ]') }
             sort keys %data),
        "\n";
    print STDERR "DEBUG[generate_asm]: use cpp = $use_cpp\n";

    if ($use_cpp) {
        my %cpp =
            platform->preprocess($target,
                                 %opts,
                                 src => $data{target} // $opts{generator}->[0],
                                 lang => 'C',
                                 clean => 1);
        %data = ( target => $cpp{target},
                  deps => $cpp{deps},
                  cmds => [ @{$data{cmds} // []},
                            @{$cpp{cmds} // []},
                            @{$data{cleanup} // []} ] );
        delete $data{cleanup};
    }

    print STDERR "DEBUG[generate_asm]: (2) \%data:\n  ",
        join("\n  ", map { $_.' => '.(ref $data{$_} eq ''
                                      ? $data{$_}
                                      : '[ '.join("\n".' ' x (length($_) + 8),
                                                  @{$data{$_}}).' ]') }
             sort keys %data),
        "\n";

    return %data;
}

sub generate_file {
    my $self = shift;
    my $target = shift;
    my %opts = @_;

    if ($opts{generator}->[0] =~ m|\.in$|) {
        my $generator = join(' ', @{$opts{generator}});
        my $dofile = catfile($config{sourcedir}, 'util', 'dofile.pl');
        return ( target => $target,
                 deps => [ $opts{generator}->[0],
                           @{$opts{generator_deps} // []},
                           @{$opts{deps} // []},
                           $dofile ],
                 cmds => [ split /\n/, <<"_____" ] );
\$(PERL) "-I\$(BLDDIR)" "-Mconfigdata" $dofile -
    "-o$opts{buildfile}" $generator > $target
_____
    }

    my $generator = join(' ', @{$opts{generator}});
    my $generator_incs =
        join('', map { ' "-I'.$_.'"' } @{$opts{generator_incs}});
    return ( target => $target,
             deps => [ $opts{generator}->[0],
                       @{$opts{generator_deps} // []},
                       @{$opts{deps} // []} ],
             cmds => [ split /\n/, <<"_____" ] );
\$(PERL)$generator_incs $generator > $target
_____
}

sub archive_staticlib {
    my $self = shift;
    my $target = shift;
    my %opts = @_;

    my $lib = platform->staticlib($target);
    my @objs =
        map { platform->convertext($_) }
        grep { platform->isobj($_) }
        @{$opts{objs}};

    return ( target => $lib,
             deps   => [ @objs ],
             cmds   => [ "LIBRARY/CREATE/OBJECT $lib",
                         (map { "LIBRARY/REPLACE $lib $_" } @objs),
                         "- PURGE $lib" ] );
}

# This is a placeholder for compilers that do translate symbols to fit
# the linker's 31 char symbol limit.  For any compiler, we require this,
# as OpenSSL does contain symbols that are longer than 31 chars.
sub translate_export {
    croak "No translator of exported symbols";
}

sub _objopt {
    my $file_handle = shift;
    my @objs = @_;

    # The "[]" hack is because in .OPT files, each line inherits the
    # previous line's file spec as default, so if no directory spec
    # is present in the current line and the previous line has one that
    # doesn't apply, you're in for a surprise.
    #
    # The returned string represents a number of write commands with the
    # correct syntax for a set of object files, something like this:
    #
    #   WRITE WHATEVER "F1.OBJ,-"
    #   WRITE WHATEVER "F2.OBJ,-"
    #   WRITE WHATEVER "LAST.OBJ"
    return
        join(",-\"\n",
             map { my $x = $_ =~ /\[/ ? $_ : "[]".$_;
                   "\@ WRITE OPT_FILE \"$x" }
             @objs)
        ."\"";
}

sub link_sharedlib {
}

sub link_dso {
}

sub link_bin {
}

1;
