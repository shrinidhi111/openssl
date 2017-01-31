#!/usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use if $^O ne "VMS", 'File::Glob' => qw/glob/;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_proof");

plan skip_all => "test_proof is not supported for this build"
    if disabled("saw");

my @proofs = ('aes', 'aes128enc', 'aes256enc', 'aes128dec', 'aes256dec',
              'chacha', 'sha1');
plan tests => scalar @proofs;

foreach my $f (@proofs) {
    ok(run(cmd(['saw', srctop_file('proof', 'aes', 'aes.saw')])));
}
