# Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;

package TLSProxy::Message;

use constant TLS_MESSAGE_HEADER_LENGTH => 4;

#Message types
use constant {
    MT_HELLO_REQUEST => 0,
    MT_CLIENT_HELLO => 1,
    MT_SERVER_HELLO => 2,
    MT_NEW_SESSION_TICKET => 4,
    MT_ENCRYPTED_EXTENSIONS => 8,
    MT_CERTIFICATE => 11,
    MT_SERVER_KEY_EXCHANGE => 12,
    MT_CERTIFICATE_REQUEST => 13,
    MT_SERVER_HELLO_DONE => 14,
    MT_CERTIFICATE_VERIFY => 15,
    MT_CLIENT_KEY_EXCHANGE => 16,
    MT_FINISHED => 20,
    MT_CERTIFICATE_STATUS => 22,
    MT_NEXT_PROTO => 67
};

#Alert levels
use constant {
    AL_LEVEL_WARN => 1,
    AL_LEVEL_FATAL => 2
};

#Alert descriptions
use constant {
    AL_DESC_CLOSE_NOTIFY => 0,
    AL_DESC_UNEXPECTED_MESSAGE => 10,
    AL_DESC_NO_RENEGOTIATION => 100
};

my %message_type = (
    MT_HELLO_REQUEST, "HelloRequest",
    MT_CLIENT_HELLO, "ClientHello",
    MT_SERVER_HELLO, "ServerHello",
    MT_NEW_SESSION_TICKET, "NewSessionTicket",
    MT_ENCRYPTED_EXTENSIONS, "EncryptedExtensions",
    MT_CERTIFICATE, "Certificate",
    MT_SERVER_KEY_EXCHANGE, "ServerKeyExchange",
    MT_CERTIFICATE_REQUEST, "CertificateRequest",
    MT_SERVER_HELLO_DONE, "ServerHelloDone",
    MT_CERTIFICATE_VERIFY, "CertificateVerify",
    MT_CLIENT_KEY_EXCHANGE, "ClientKeyExchange",
    MT_FINISHED, "Finished",
    MT_CERTIFICATE_STATUS, "CertificateStatus",
    MT_NEXT_PROTO, "NextProto"
);

use constant {
    EXT_SERVER_NAME => 0,
    EXT_MAX_FRAGMENT_LENGTH => 1,
    EXT_STATUS_REQUEST => 5,
    EXT_SUPPORTED_GROUPS => 10,
    EXT_EC_POINT_FORMATS => 11,
    EXT_SRP => 12,
    EXT_SIG_ALGS => 13,
    EXT_USE_SRTP => 14,
    EXT_ALPN => 16,
    EXT_SCT => 18,
    EXT_PADDING => 21,
    EXT_ENCRYPT_THEN_MAC => 22,
    EXT_EXTENDED_MASTER_SECRET => 23,
    EXT_SESSION_TICKET => 35,
    EXT_KEY_SHARE => 51,
    EXT_PSK => 41,
    EXT_SUPPORTED_VERSIONS => 43,
    EXT_COOKIE => 44,
    EXT_PSK_KEX_MODES => 45,
    EXT_POST_HANDSHAKE_AUTH => 49,
    EXT_SIG_ALGS_CERT => 50,
    EXT_RENEGOTIATE => 65281,
    EXT_NPN => 13172,
    # This extension is an unofficial extension only ever written by OpenSSL
    # (i.e. not read), and even then only when enabled. We use it to test
    # handling of duplicate extensions.
    EXT_DUPLICATE_EXTENSION => 0xfde8,
    EXT_UNKNOWN => 0xfffe,
    #Unknown extension that should appear last
    EXT_FORCE_LAST => 0xffff
};

# SignatureScheme of TLS 1.3, from
# https://tools.ietf.org/html/draft-ietf-tls-tls13-20#appendix-B.3.1.3
# TODO(TLS1.3) update link to IANA registry after publication
# We have to manually grab the SHA224 equivalents from the old registry
use constant {
    SIG_ALG_RSA_PKCS1_SHA256 => 0x0401,
    SIG_ALG_RSA_PKCS1_SHA384 => 0x0501,
    SIG_ALG_RSA_PKCS1_SHA512 => 0x0601,
    SIG_ALG_ECDSA_SECP256R1_SHA256 => 0x0403,
    SIG_ALG_ECDSA_SECP384R1_SHA384 => 0x0503,
    SIG_ALG_ECDSA_SECP521R1_SHA512 => 0x0603,
    SIG_ALG_RSA_PSS_SHA256 => 0x0804,
    SIG_ALG_RSA_PSS_SHA384 => 0x0805,
    SIG_ALG_RSA_PSS_SHA512 => 0x0806,
    SIG_ALG_ED25519 => 0x0807,
    SIG_ALG_ED448 => 0x0808,
    SIG_ALG_RSA_PKCS1_SHA1 => 0x0201,
    SIG_ALG_ECDSA_SHA1 => 0x0203,
    SIG_ALG_DSA_SHA1 => 0x0202,
    SIG_ALG_DSA_SHA256 => 0x0402,
    SIG_ALG_DSA_SHA384 => 0x0502,
    SIG_ALG_DSA_SHA512 => 0x0602,
    OSSL_SIG_ALG_RSA_PKCS1_SHA224 => 0x0301,
    OSSL_SIG_ALG_DSA_SHA224 => 0x0302,
    OSSL_SIG_ALG_ECDSA_SHA224 => 0x0303
};

use constant {
    CIPHER_DHE_RSA_AES_128_SHA => 0x0033,
    CIPHER_ADH_AES_128_SHA => 0x0034,
    CIPHER_TLS13_AES_128_GCM_SHA256 => 0x1301,
    CIPHER_TLS13_AES_256_GCM_SHA384 => 0x1302
};

my $payload = "";
my $messlen = -1;
my $mt;
my $startoffset = -1;
my $server = 0;
my $success = 0;
my $end = 0;
my @message_rec_list = ();
my @message_frag_lens = ();
my $ciphersuite = 0;
my $successondata = 0;

sub clear
{
    $payload = "";
    $messlen = -1;
    $startoffset = -1;
    $server = 0;
    $success = 0;
    $end = 0;
    $successondata = 0;
    @message_rec_list = ();
    @message_frag_lens = ();
}

#Class method to extract messages from a record
sub get_messages
{
    my $class = shift;
    my $serverin = shift;
    my $record = shift;
    my @messages = ();
    my $message;

    @message_frag_lens = ();

    if ($serverin != $server && length($payload) != 0) {
        die "Changed peer ($server => $serverin), but we still have fragment data\n";
    }
    $server = $serverin;

    if ($record->content_type == TLSProxy::Record::RT_CCS) {
        if ($payload ne "") {
            #We can't handle this yet
            die "CCS received before message data complete\n";
        }
        if (!TLSProxy::Proxy->is_tls13()) {
            if ($server) {
                TLSProxy::Record->server_encrypting(1);
            } else {
                TLSProxy::Record->client_encrypting(1);
            }
        }
    } elsif ($record->content_type == TLSProxy::Record::RT_HANDSHAKE) {
        if ($record->len == 0 || $record->len_real == 0) {
            print "  Message truncated\n";
        } else {
            my $recoffset = 0;

            if (length $payload > 0) {
                #We are continuing processing a message started in a previous
                #record. Add this record to the list associated with this
                #message
                push @message_rec_list, $record;

                if ($messlen <= length($payload)) {
                    #Shouldn't happen
                    die "Internal error: invalid messlen: ".$messlen
                        ." payload length:".length($payload)."\n";
                }
                if (length($payload) + $record->decrypt_len >= $messlen) {
                    #We can complete the message with this record
                    $recoffset = $messlen - length($payload);
                    $payload .= substr($record->decrypt_data, 0, $recoffset);
                    push @message_frag_lens, $recoffset;
                    $message = create_message($server, $mt, $payload,
                                              $startoffset);
                    push @messages, $message;

                    $payload = "";
                } else {
                    #This is just part of the total message
                    $payload .= $record->decrypt_data;
                    $recoffset = $record->decrypt_len;
                    push @message_frag_lens, $record->decrypt_len;
                }
                print "  Partial message data read: ".$recoffset." bytes\n";
            }

            while ($record->decrypt_len > $recoffset) {
                #We are at the start of a new message
                if ($record->decrypt_len - $recoffset < 4) {
                    #Whilst technically probably valid we can't cope with this
                    die "End of record in the middle of a message header\n";
                }
                @message_rec_list = ($record);
                my $lenhi;
                my $lenlo;
                ($mt, $lenhi, $lenlo) = unpack('CnC',
                                               substr($record->decrypt_data,
                                                      $recoffset));
                $messlen = ($lenhi << 8) | $lenlo;
                print "  Message type: $message_type{$mt}\n";
                print "  Message Length: $messlen\n";
                $startoffset = $recoffset;
                $recoffset += 4;
                $payload = "";
                
                if ($recoffset <= $record->decrypt_len) {
                    #Some payload data is present in this record
                    if ($record->decrypt_len - $recoffset >= $messlen) {
                        #We can complete the message with this record
                        $payload .= substr($record->decrypt_data, $recoffset,
                                           $messlen);
                        $recoffset += $messlen;
                        push @message_frag_lens, $messlen;
                        $message = create_message($server, $mt, $payload,
                                                  $startoffset);
                        push @messages, $message;

                        $payload = "";
                    } else {
                        #This is just part of the total message
                        $payload .= substr($record->decrypt_data, $recoffset,
                                           $record->decrypt_len - $recoffset);
                        $recoffset = $record->decrypt_len;
                        push @message_frag_lens, $recoffset;
                    }
                }
            }
        }
    } elsif ($record->content_type == TLSProxy::Record::RT_APPLICATION_DATA) {
        print "  [ENCRYPTED APPLICATION DATA]\n";
        print "  [".$record->decrypt_data."]\n";

        if ($successondata) {
            $success = 1;
            $end = 1;
        }
    } elsif ($record->content_type == TLSProxy::Record::RT_ALERT) {
        my ($alertlev, $alertdesc) = unpack('CC', $record->decrypt_data);
        #A CloseNotify from the client indicates we have finished successfully
        #(we assume)
        if (!$end && !$server && $alertlev == AL_LEVEL_WARN
            && $alertdesc == AL_DESC_CLOSE_NOTIFY) {
            $success = 1;
        }
        #All alerts end the test
        $end = 1;
    }

    return @messages;
}

#Function to work out which sub-class we need to create and then
#construct it
sub create_message
{
    my ($server, $mt, $data, $startoffset) = @_;
    my $message;

    #We only support ClientHello in this version...needs to be extended for
    #others
    if ($mt == MT_CLIENT_HELLO) {
        $message = TLSProxy::ClientHello->new(
            $server,
            $data,
            [@message_rec_list],
            $startoffset,
            [@message_frag_lens]
        );
        $message->parse();
    } elsif ($mt == MT_SERVER_HELLO) {
        $message = TLSProxy::ServerHello->new(
            $server,
            $data,
            [@message_rec_list],
            $startoffset,
            [@message_frag_lens]
        );
        $message->parse();
    } elsif ($mt == MT_ENCRYPTED_EXTENSIONS) {
        $message = TLSProxy::EncryptedExtensions->new(
            $server,
            $data,
            [@message_rec_list],
            $startoffset,
            [@message_frag_lens]
        );
        $message->parse();
    } elsif ($mt == MT_CERTIFICATE) {
        $message = TLSProxy::Certificate->new(
            $server,
            $data,
            [@message_rec_list],
            $startoffset,
            [@message_frag_lens]
        );
        $message->parse();
    } elsif ($mt == MT_CERTIFICATE_VERIFY) {
        $message = TLSProxy::CertificateVerify->new(
            $server,
            $data,
            [@message_rec_list],
            $startoffset,
            [@message_frag_lens]
        );
        $message->parse();
    } elsif ($mt == MT_SERVER_KEY_EXCHANGE) {
        $message = TLSProxy::ServerKeyExchange->new(
            $server,
            $data,
            [@message_rec_list],
            $startoffset,
            [@message_frag_lens]
        );
        $message->parse();
    } elsif ($mt == MT_NEW_SESSION_TICKET) {
        $message = TLSProxy::NewSessionTicket->new(
            $server,
            $data,
            [@message_rec_list],
            $startoffset,
            [@message_frag_lens]
        );
        $message->parse();
    } else {
        #Unknown message type
        $message = TLSProxy::Message->new(
            $server,
            $mt,
            $data,
            [@message_rec_list],
            $startoffset,
            [@message_frag_lens]
        );
    }

    return $message;
}

sub end
{
    my $class = shift;
    return $end;
}
sub success
{
    my $class = shift;
    return $success;
}
sub fail
{
    my $class = shift;
    return !$success && $end;
}
sub new
{
    my $class = shift;
    my ($server,
        $mt,
        $data,
        $records,
        $startoffset,
        $message_frag_lens) = @_;
    
    my $self = {
        server => $server,
        data => $data,
        records => $records,
        mt => $mt,
        startoffset => $startoffset,
        message_frag_lens => $message_frag_lens
    };

    return bless $self, $class;
}

sub ciphersuite
{
    my $class = shift;
    if (@_) {
      $ciphersuite = shift;
    }
    return $ciphersuite;
}

#Update all the underlying records with the modified data from this message
#Note: Only supports re-encrypting for TLSv1.3
sub repack
{
    my $self = shift;
    my $msgdata;

    my $numrecs = $#{$self->records};

    $self->set_message_contents();

    my $lenhi;
    my $lenlo;

    $lenlo = length($self->data) & 0xff;
    $lenhi = length($self->data) >> 8;
    $msgdata = pack('CnC', $self->mt, $lenhi, $lenlo).$self->data;

    if ($numrecs == 0) {
        #The message is fully contained within one record
        my ($rec) = @{$self->records};
        my $recdata = $rec->decrypt_data;

        my $old_length;

        # We use empty message_frag_lens to indicates that pre-repacking,
        # the message wasn't present. The first fragment length doesn't include
        # the TLS header, so we need to check and compute the right length.
        if (@{$self->message_frag_lens}) {
            $old_length = ${$self->message_frag_lens}[0] +
              TLS_MESSAGE_HEADER_LENGTH;
        } else {
            $old_length = 0;
        }

        my $prefix = substr($recdata, 0, $self->startoffset);
        my $suffix = substr($recdata, $self->startoffset + $old_length);

        $rec->decrypt_data($prefix.($msgdata).($suffix));
        # TODO(openssl-team): don't keep explicit lengths.
        # (If a length override is ever needed to construct invalid packets,
        #  use an explicit override field instead.)
        $rec->decrypt_len(length($rec->decrypt_data));
        $rec->len($rec->len + length($msgdata) - $old_length);
        # Only support re-encryption for TLSv1.3.
        if (TLSProxy::Proxy->is_tls13() && $rec->encrypted()) {
            #Add content type (1 byte) and 16 tag bytes
            $rec->data($rec->decrypt_data
                .pack("C", TLSProxy::Record::RT_HANDSHAKE).("\0"x16));
        } else {
            $rec->data($rec->decrypt_data);
        }

        #Update the fragment len in case we changed it above
        ${$self->message_frag_lens}[0] = length($msgdata)
                                         - TLS_MESSAGE_HEADER_LENGTH;
        return;
    }

    #Note we don't currently support changing a fragmented message length
    my $recctr = 0;
    my $datadone = 0;
    foreach my $rec (@{$self->records}) {
        my $recdata = $rec->decrypt_data;
        if ($recctr == 0) {
            #This is the first record
            my $remainlen = length($recdata) - $self->startoffset;
            $rec->data(substr($recdata, 0, $self->startoffset)
                       .substr(($msgdata), 0, $remainlen));
            $datadone += $remainlen;
        } elsif ($recctr + 1 == $numrecs) {
            #This is the last record
            $rec->data(substr($msgdata, $datadone));
        } else {
            #This is a middle record
            $rec->data(substr($msgdata, $datadone, length($rec->data)));
            $datadone += length($rec->data);
        }
        $recctr++;
    }
}

#To be overridden by sub-classes
sub set_message_contents
{
}

#Read only accessors
sub server
{
    my $self = shift;
    return $self->{server};
}

#Read/write accessors
sub mt
{
    my $self = shift;
    if (@_) {
      $self->{mt} = shift;
    }
    return $self->{mt};
}
sub data
{
    my $self = shift;
    if (@_) {
      $self->{data} = shift;
    }
    return $self->{data};
}
sub records
{
    my $self = shift;
    if (@_) {
      $self->{records} = shift;
    }
    return $self->{records};
}
sub startoffset
{
    my $self = shift;
    if (@_) {
      $self->{startoffset} = shift;
    }
    return $self->{startoffset};
}
sub message_frag_lens
{
    my $self = shift;
    if (@_) {
      $self->{message_frag_lens} = shift;
    }
    return $self->{message_frag_lens};
}
sub encoded_length
{
    my $self = shift;
    return TLS_MESSAGE_HEADER_LENGTH + length($self->data);
}
sub successondata
{
    my $class = shift;
    if (@_) {
        $successondata = shift;
    }
    return $successondata;
}
1;
