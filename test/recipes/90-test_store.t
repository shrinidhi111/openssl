#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use MIME::Base64;
use OpenSSL::Test qw(:DEFAULT srctop_file bldtop_file);

my $test_name = "test_store";
setup($test_name);

my @src_files =
    ( "test/testx509.pem",
      "test/testrsa.pem",
      "test/testrsapub.pem",
      "test/testcrl.pem",
      "apps/server.pem" );
my @generated_files =
    (
     ### generated from the source files

     "testx509.der",
     "testrsa.der",
     "testrsapub.der",
     "testcrl.der",

     ### generated locally
     ### These examples were pilfered from OpenConnect's test suite

     "user-key-pkcs1.pem", "user-key-pkcs1.der",
     "user-key-pkcs1-aes128.pem",
     "user-key-pkcs8.pem", "user-key-pkcs8.der",
     "user-key-pkcs8-pbes1-sha1-3des.pem", "user-key-pkcs8-pbes1-sha1-3des.der",
     "user-key-pkcs8-pbes2-sha1.pem", "user-key-pkcs8-pbes2-sha1.der",
     "user-key-sha1-3des-sha1.p12", "user-key-sha1-3des-sha256.p12",
     "user-key-aes256-cbc-sha256.p12",
     "user-key-md5-des-sha1.p12",
     "user-key-aes256-cbc-md5-des-sha256.p12",
     "user-key-pkcs8-pbes2-sha256.pem", "user-key-pkcs8-pbes2-sha256.der",
     "user-key-pkcs8-pbes1-md5-des.pem", "user-key-pkcs8-pbes1-md5-des.der",
     "dsa-key-pkcs1.pem", "dsa-key-pkcs1.der",
     "dsa-key-pkcs1-aes128.pem",
     "dsa-key-pkcs8.pem", "dsa-key-pkcs8.der",
     "dsa-key-pkcs8-pbes2-sha1.pem", "dsa-key-pkcs8-pbes2-sha1.der",
     "dsa-key-aes256-cbc-sha256.p12",
     "ec-key-pkcs1.pem", "ec-key-pkcs1.der",
     "ec-key-pkcs1-aes128.pem",
     "ec-key-pkcs8.pem", "ec-key-pkcs8.der",
     "ec-key-pkcs8-pbes2-sha1.pem", "ec-key-pkcs8-pbes2-sha1.der",
     "ec-key-aes256-cbc-sha256.p12",
    );

my $n = scalar @src_files + scalar @generated_files;

plan tests => $n;

indir "store_$$" => sub {
 SKIP:
    {
        skip "failed initialisation", $n unless init();

        foreach (@src_files) {
            ok(run(app(["openssl", "storeutl", srctop_file($_)])));
        }
        foreach (@generated_files) {
        SKIP:
            {
                skip "PKCS#12 files not currently supported", 1 if m|\.p12$|;

                ok(run(app(["openssl", "storeutl", "-passin", "pass:password",
                            $_])));
            }
        }
    }
}, create => 1, cleanup => 0;

sub init {
    return (
            # user-key-pkcs1.pem
            run(app(["openssl", "genrsa",
                     "-out", "user-key-pkcs1.pem", "2432"]))
            # dsa-key-pkcs1.pem
            && run(app(["openssl", "dsaparam", "-genkey",
                        "-out", "dsa-key-pkcs1.pem", "1024"]))
            # ec-key-pkcs1.pem (one might think that 'genec' would be practical)
            && run(app(["openssl", "ecparam", "-genkey", "-name", "prime256v1",
                        "-out", "ec-key-pkcs1.pem"]))
            # user-key-pkcs1-aes128.pem
            && run(app(["openssl", "rsa", "-passout", "pass:password", "-aes128",
                        "-in", "user-key-pkcs1.pem",
                        "-out", "user-key-pkcs1-aes128.pem"]))
            # dsa-key-pkcs1-aes128.pem
            && run(app(["openssl", "dsa", "-passout", "pass:password", "-aes128",
                        "-in", "dsa-key-pkcs1.pem",
                        "-out", "dsa-key-pkcs1-aes128.pem"]))
            # ec-key-pkcs1-aes128.pem
            && run(app(["openssl", "ec", "-passout", "pass:password", "-aes128",
                        "-in", "ec-key-pkcs1.pem",
                        "-out", "ec-key-pkcs1-aes128.pem"]))
            # *-key-pkcs8.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8\.pem$/-key-pkcs1.pem/i;
                          run(app(["openssl", "pkcs8", "-topk8", "-nocrypt",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8\.pem$/, @generated_files))
            # *-key-pkcs8-pbes1-sha1-3des.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8-pbes1-sha1-3des\.pem$
                                  /-key-pkcs8.pem/ix;
                          run(app(["openssl", "pkcs8", "-topk8",
                                   "-passout", "pass:password",
                                   "-v1", "pbeWithSHA1And3-KeyTripleDES-CBC",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8-pbes1-sha1-3des\.pem$/, @generated_files))
            # *-key-pkcs8-pbes1-md5-des.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8-pbes1-md5-des\.pem$
                                  /-key-pkcs8.pem/ix;
                          run(app(["openssl", "pkcs8", "-topk8",
                                   "-passout", "pass:password",
                                   "-v1", "pbeWithSHA1And3-KeyTripleDES-CBC",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8-pbes1-md5-des\.pem$/, @generated_files))
            # *-key-pkcs8-pbes2-sha1.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8-pbes2-sha1\.pem$
                                  /-key-pkcs8.pem/ix;
                          run(app(["openssl", "pkcs8", "-topk8",
                                   "-passout", "pass:password",
                                   "-v2", "aes256", "-v2prf", "hmacWithSHA1",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8-pbes2-sha1\.pem$/, @generated_files))
            # *-key-pkcs8-pbes2-sha1.pem
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile)
                              =~ s/-key-pkcs8-pbes2-sha256\.pem$
                                  /-key-pkcs8.pem/ix;
                          run(app(["openssl", "pkcs8", "-topk8",
                                   "-passout", "pass:password",
                                   "-v2", "aes256", "-v2prf", "hmacWithSHA256",
                                   "-in", $srcfile, "-out", $dstfile]));
                      }, grep(/-key-pkcs8-pbes2-sha256\.pem$/, @generated_files))
            # *.der (the end all init)
            && runall(sub {
                          my $dstfile = shift;
                          (my $srcfile = $dstfile) =~ s/\.der$/.pem/i;
                          if (! -f $srcfile) {
                              $srcfile = srctop_file("test", $srcfile);
                          }
                          my $infh;
                          unless (open $infh, $srcfile) {
                              return 0;
                          }
                          my $l;
                          while (($l = <$infh>) !~ /^-----BEGIN\s/
                                 || $l =~ /^-----BEGIN.*PARAMETERS-----/) {
                          }
                          my $b64 = "";
                          while (($l = <$infh>) !~ /^-----END\s/) {
                              $l =~ s|\R$||;
                              $b64 .= $l unless $l =~ /:/;
                          }
                          close $infh;
                          my $der = decode_base64($b64);
                          unless (length($b64) / 4 * 3 - length($der) < 3) {
                              print STDERR "Length error, ",length($b64),
                                  " bytes of base64 became ",length($der),
                                  " bytes of der? ($srcfile => $dstfile)\n";
                              return 0;
                          }
                          my $outfh;
                          unless (open $outfh, ">:raw", $dstfile) {
                              return 0;
                          }
                          print $outfh $der;
                          close $outfh;
                          return 1;
                      }, grep(/\.der$/, @generated_files))
           );
}

sub runall {
    my ($function, @items) = @_;

    foreach (@items) {
        return 0 unless $function->($_);
    }
    return 1;
}
