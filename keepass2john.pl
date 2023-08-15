#!/usr/bin/perl

use strict;
use warnings;
use feature qw(say);
use File::Basename;
use Digest::MD5 qw(md5_hex);
use utf8;
use Encode;

sub process_1x_database {
    my ($data, $databaseName, $maxInlineSize) = @_;
    my $index = 8;
    my $algorithm = -1;

    my ($encFlag) = unpack("<L", substr($data, $index, 4));
    $index += 4;
    if ($encFlag & 2 == 2) {
        # AES
        $algorithm = 0;
    }
    elsif ($encFlag & 8) {
        # Twofish
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

    return "$databaseName<SHOULD_BE_REMOVED_INCLUDING_COLON>:\\\$keepass\$*1*$keyTransformRounds*$algorithm*$finalRandomseed*$transformRandomseed*$encIV*$contentsHash*$end";
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
            ($transformRounds) = unpack("S", substr($data, $index, 2));
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

    return "$databaseName<SHOULD_BE_REMOVED_INCLUDING_COLON>:\$keepass\$*2*$transformRounds*$dataStartOffset*$masterSeed*$transformSeed*$initializationVectors*$expectedStartBytes*$firstEncryptedBytes";
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

    if ($fileSignature eq '03d9a29a67fb4bb5') {
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
