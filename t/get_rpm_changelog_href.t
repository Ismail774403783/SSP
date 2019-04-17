#!/usr/local/cpanel/3rdparty/bin/perl

use strict;
use warnings;
use Data::Dumper;
require './ssp';
use lib '/usr/local/cpanel/3rdparty/perl/528/lib/perl5/cpanel_lib';
use Test::MockModule;
use Test::Simple tests => 3;

my $mock = Test::MockModule->new('SSP');
$mock->mock( timed_run => sub {
    my $changelog = q{
         #^#openssl#^#1.0.2k
        - fix CVE-2014-0224 fix that broke EAP-FAST session resumption support
        - fix CVE-2014-0224 - SSL/TLS MITM vulnerability
        - fix CVE-2014-0160 - information disclosure in TLS heartbeat extension
        #^#dovecot#^#2.3.4.1
        - Applied upstream patches for CVE-2019-7524
   };
    $changelog =~ s/^[\s\n]+//mg;
    return $changelog;
} );

my $changelog_href = SSP::get_rpm_changelog_href();

ok( $changelog_href->{dovecot}->{'CVE-2019-7524'}->{seen} eq 1, 'Checking dovecot for CVE-2019-7524' );
ok( $changelog_href->{openssl}->{'CVE-2014-0224'}->{seen} eq 1, 'Checking openssl for CVE-2014-0224' );
ok( $changelog_href->{openssl}->{'CVE-2014-0160'}->{seen} eq 1, 'Checking openssl for CVE-2014-0160' );
