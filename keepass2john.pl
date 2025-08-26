#!/usr/bin/perl

use strict;
use warnings;
use feature qw(say);
use File::Basename;
use utf8;
use Encode;

sub process_1x_database {
    my ($data, $databaseName, $maxInlineSize) = @_;
    my $index = 8;
    my $algorithm = -1;

    my ($encFlag) = unpack("<L", substr($data, $index, 4));
    $index += 4;
    if ($encFlag & 2 == 2) {
        $algorithm = 0;
    }
    elsif ($encFlag & 8) {
        $algorithm = 1;
    }
    else {
        say "Unsupported file encryption!";
        return;
    }

    my ($keyfileSize) = unpack("<L", substr($data, $index, 4));
    $index += 4;
    my $keyfile = unpack("H*", substr($data, $index, $keyfileSize));
    $index += $keyfileSize;

    my $version = unpack("H*", substr($data, $index, 4));
    $index += 4;

    my $finalRandomseed = encode_utf8(unpack("H*", substr($data, $index, 16)));
    $index += 16;

    my $encIV = encode_utf8(unpack("H*", substr($data, $index, 16)));
    $index += 16;

    my ($numGroups) = unpack("<L", substr($data, $index, 4));
    $index += 4;
    my ($numEntries) = unpack("<L", substr($data, $index, 4));
    $index += 4;

    my $contentsHash = encode_utf8(unpack("H*", substr($data, $index, 32)));
    $index += 32;

    my $transformRandomseed = encode_utf8(unpack("H*", substr($data, $index, 32)));
    $index += 32;

    my ($keyTransformRounds) = unpack("<L", substr($data, $index, 4));

    my $filesize = length($data);
    my $datasize = $filesize - 124;

    my $dataBuffer = unpack("H*", substr($data, 124));
    my $end;
    if (($filesize + $datasize) < $maxInlineSize) {
        $end = "*1*$datasize*$dataBuffer";
    }
    else {
        $end = "0*$databaseName";
    }

    return "$databaseName:\$keepass\$*1*$keyTransformRounds*$algorithm*$finalRandomseed*$transformRandomseed*$encIV*$contentsHash*$end";
}

sub process_2x_database {
    my ($data, $databaseName) = @_;
    my $index = 12;
    my $endReached = 0;
    my ($masterSeed, $transformSeed, $transformRounds, $initializationVectors, $expectedStartBytes);

    while (!$endReached) {
        my ($btFieldID) = unpack("C", substr($data, $index, 1));
        $index += 1;
        my ($uSize) = unpack("S", substr($data, $index, 2));
        $index += 2;

        if ($btFieldID == 0) {
            $endReached = 1;
        }

        if ($btFieldID == 4) {
            $masterSeed = encode_utf8(unpack("H*", substr($data, $index, $uSize)));
        }

        if ($btFieldID == 5) {
            $transformSeed = encode_utf8(unpack("H*", substr($data, $index, $uSize)));
        }

        if ($btFieldID == 6) {
            ($transformRounds) = unpack("Q<", substr($data, $index, 8));
        }

        if ($btFieldID == 7) {
            $initializationVectors = encode_utf8(unpack("H*", substr($data, $index, $uSize)));
        }

        if ($btFieldID == 9) {
            $expectedStartBytes = encode_utf8(unpack("H*", substr($data, $index, $uSize)));
        }

        $index += $uSize;
    }

    my $dataStartOffset = $index;
    my $firstEncryptedBytes = encode_utf8(unpack("H*", substr($data, $index, 32)));

    return "$databaseName:\$keepass\$*2*$transformRounds*$dataStartOffset*$masterSeed*$transformSeed*$initializationVectors*$expectedStartBytes*$firstEncryptedBytes";
}

sub parse_kdf_parameters {
    my ($kdf_data) = @_;
    my %params;
    my $index = 0;
    
    return %params unless $kdf_data;
    
    my ($version) = unpack("v", substr($kdf_data, $index, 2));
    $index += 2;
    
    while ($index < length($kdf_data)) {
        my ($value_type) = unpack("C", substr($kdf_data, $index, 1));
        $index += 1;
        last if $value_type == 0;
        
        my ($key_len) = unpack("V", substr($kdf_data, $index, 4));
        $index += 4;
        my $key_name = substr($kdf_data, $index, $key_len);
        $index += $key_len;
        
        my ($val_len) = unpack("V", substr($kdf_data, $index, 4));
        $index += 4;
        
        if ($val_len > 0) {
            my $value = substr($kdf_data, $index, $val_len);
            $index += $val_len;
            
            if ($value_type == 0x04 && $val_len == 4) {
                $params{$key_name} = unpack("V", $value);
            }
            elsif ($value_type == 0x05 && $val_len == 8) {
                $params{$key_name} = unpack("Q<", $value);
            }
            elsif ($value_type == 0x08 && $val_len == 1) {
                $params{$key_name} = unpack("C", $value);
            }
            elsif ($value_type == 0x18) {
                $params{$key_name} = $value;
            }
            elsif ($value_type == 0x42) {
                $params{$key_name} = $value;
                if ($key_name eq '$UUID' && length($value) >= 16) {
                    $params{'$UUID_bytes'} = $value;
                }
            }
        }
    }
    
    return %params;
}

sub process_kdbx4_database {
    my ($filename) = @_;
    open(my $fh, '<:raw', $filename) or die "Could not open file '$filename': $!";
    
    read($fh, my $sig_bytes, 8);
    my ($sig1, $sig2) = unpack("II", $sig_bytes);
    die "Not a valid KDBX4 file" unless $sig1 == 0x9AA2D903 && $sig2 == 0xB54BFB67;
    
    read($fh, my $version_bytes, 4);
    my ($version) = unpack("I", $version_bytes);
    
    seek($fh, 0, 0);
    read($fh, my $complete_header_data, 12);
    
    my %header_fields;
    my $header_start_pos = tell($fh);
    
    while (1) {
        read($fh, my $field_id_byte, 1);
        last unless $field_id_byte;
        my ($field_id) = unpack("C", $field_id_byte);
        last if $field_id == 0;
        
        read($fh, my $field_size_bytes, 4);
        my ($field_size) = unpack("V", $field_size_bytes);
        read($fh, my $field_data, $field_size);
        $header_fields{$field_id} = $field_data;
        $complete_header_data .= $field_id_byte . $field_size_bytes . $field_data;
    }
    
    $complete_header_data .= "\x00";
    my $header_end_pos = tell($fh);
    
    read($fh, my $header_hash, 32);
    read($fh, my $header_hmac, 40);
    close($fh);
    
    my $master_seed = $header_fields{4} || '';
    my $kdf_params_data = $header_fields{11} || '';
    
    my %kdf_params = parse_kdf_parameters($kdf_params_data);
    
    my $kdf_uuid_str = "00000000";
    if ($kdf_params{'$UUID'} && length($kdf_params{'$UUID'}) >= 4) {
        my ($uuid_le) = unpack("V", substr($kdf_params{'$UUID'}, 0, 4));
        my $uuid_be = unpack("N", pack("V", $uuid_le));
        $kdf_uuid_str = sprintf("%08x", $uuid_be);
    }
    
    my $iterations = $kdf_params{'I'} || $kdf_params{'R'} || 0;
    my $memory = $kdf_params{'M'} || 0;
    my $parallelism = $kdf_params{'P'} || 0;
    my $salt = $kdf_params{'S'} || '';
    my $v = $kdf_params{'V'} || 0;
    
    my $database_name = basename($filename);
    my $master_seed_hex = unpack("H*", $master_seed);
    my $salt_hex = unpack("H*", $salt);
    my $header_data_hex = unpack("H*", $complete_header_data);
    my $header_hmac_hex = unpack("H*", $header_hmac);
    
    return "$database_name:\$keepass\$*4*$iterations*$kdf_uuid_str*$memory*$v*$parallelism*$master_seed_hex*$salt_hex*$header_data_hex*$header_hmac_hex";
}

sub process_3x_database {
    my ($data, $databaseName) = @_;
    my $index = 12;
    my $endReached = 0;
    my ($masterSeed, $transformSeed, $transformRounds, $initializationVectors, $expectedStartBytes, $kdfParamsData);
    my $algorithm = 0;

    while (!$endReached) {
        my ($btFieldID) = unpack("C", substr($data, $index, 1));
        $index += 1;
        my ($uSize) = unpack("V", substr($data, $index, 4));
        $index += 4;

        if ($btFieldID == 0) {
            $endReached = 1;
            next;
        }

        if ($btFieldID == 2) {
            my $cipher_id = substr($data, $index, $uSize);
            if ($cipher_id =~ /^\x31\xc1\xf2\xe6/) {
                $algorithm = 0;
            }
            elsif ($cipher_id =~ /^\xad\x68\xf2\x9f/) {
                $algorithm = 1;
            }
            elsif ($cipher_id =~ /^\xd6\x03\x8a\x2b/) {
                $algorithm = 2;
            }
        }

        if ($btFieldID == 4) {
            $masterSeed = substr($data, $index, $uSize);
        }

        if ($btFieldID == 5) {
            $transformSeed = substr($data, $index, $uSize);
        }

        if ($btFieldID == 6) {
            ($transformRounds) = unpack("V", substr($data, $index, 4));
        }

        if ($btFieldID == 7) {
            $initializationVectors = substr($data, $index, $uSize);
        }

        if ($btFieldID == 9) {
            $expectedStartBytes = substr($data, $index, $uSize);
        }

        if ($btFieldID == 11) {
            $kdfParamsData = substr($data, $index, $uSize);
        }

        $index += $uSize;
    }

    my $header_hash = substr($data, $index, 32);
    $index += 32;
    my $header_hmac = substr($data, $index, 32);
    $index += 32;
    my $first_encrypted_bytes = substr($data, $index, 32);

    if ($kdfParamsData) {
        my %kdf_params = parse_kdf_parameters($kdfParamsData);
        
        my $kdf_uuid_str = "00000000";
        if ($kdf_params{'$UUID_bytes'} && length($kdf_params{'$UUID_bytes'}) >= 4) {
            my ($uuid_le) = unpack("V", substr($kdf_params{'$UUID_bytes'}, 0, 4));
            $kdf_uuid_str = sprintf("%08x", $uuid_le);
            $kdf_uuid_str = join('', reverse($kdf_uuid_str =~ /../g));
        }
        
        my $iterations = $kdf_params{'I'} || $kdf_params{'R'} || $transformRounds;
        my $memory = $kdf_params{'M'} || 0;
        my $parallelism = $kdf_params{'P'} || 0;
        my $salt = $kdf_params{'S'} || $transformSeed;
        
        my $complete_header_data = substr($data, 0, $index);
        my $master_seed_hex = unpack("H*", $masterSeed);
        my $salt_hex = unpack("H*", $salt);
        my $header_data_hex = unpack("H*", $complete_header_data);
        my $header_hmac_hex = unpack("H*", $header_hmac);
        
        return "$databaseName:\$keepass\$*4*$iterations*$kdf_uuid_str*$memory*$parallelism*" . length($complete_header_data) . "*$master_seed_hex*$salt_hex*$header_data_hex*$header_hmac_hex";
    }
    else {
        my $master_seed_hex = unpack("H*", $masterSeed);
        my $transform_seed_hex = unpack("H*", $transformSeed);
        my $iv_hex = unpack("H*", $initializationVectors);
        my $start_bytes_hex = unpack("H*", $expectedStartBytes);
        my $header_hash_hex = unpack("H*", $header_hash);
        my $header_hmac_hex = unpack("H*", $header_hmac);
        my $encrypted_bytes_hex = unpack("H*", $first_encrypted_bytes);
        
        return "$databaseName:\$keepass\$*3*$transformRounds*$algorithm*$master_seed_hex*$transform_seed_hex*$iv_hex*$start_bytes_hex*$header_hash_hex*$header_hmac_hex*$encrypted_bytes_hex";
    }
}

sub process_database {
    my ($filename) = @_;
    open(my $fh, '<:raw', $filename) or die "Could not open file '$filename': $!";
    my $data;
    {
        local $/;
        $data = <$fh>;
    }
    close($fh);

    my $base = basename($filename);
    my $databaseName = (split /\./, $base)[0];

    my $fileSignature = unpack("H*", substr($data, 0, 8));
    my ($version) = unpack("I", substr($data, 8, 4));

    if ($version >= 0x00040000) {
        say process_kdbx4_database($filename);
    }
    elsif ($version == 0x00030001) {
        say process_3x_database($data, $databaseName);
    }
    elsif ($fileSignature eq '03d9a29a67fb4bb5') {
        say process_2x_database($data, $databaseName);
    }
    elsif ($fileSignature eq '03d9a29a66fb4bb5') {
        say process_2x_database($data, $databaseName);
    }
    elsif ($fileSignature eq '03d9a29a65fb4bb5') {
        say process_1x_database($data, $databaseName, 1024);
    }
    else {
        say "ERROR: KeePass signature unrecognized";
    }
}

if (@ARGV < 1) {
    die "Usage: $0 <kdb[x] file[s]>\n";
}

foreach my $filename (@ARGV) {
    process_database($filename);
}
