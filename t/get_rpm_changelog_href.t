#!/usr/local/cpanel/3rdparty/bin/perl

use strict;
use warnings;
require './ssp';
use lib '/usr/local/cpanel/3rdparty/perl/528/lib/perl5/cpanel_lib';
use Test::MockModule;
use Test::Simple tests => 7;

my $mock = Test::MockModule->new('SSP');
$mock->mock( timed_run => sub {
    my $changelog = q{
         #^#openssl#^#1.0.2k
        - fix CVE-2014-0224 fix that broke EAP-FAST session resumption support
        - fix CVE-2014-0224 - SSL/TLS MITM vulnerability
        - fix CVE-2014-0160 - information disclosure in TLS heartbeat extension
        #^#dovecot#^#2.3.4.1
        - Applied upstream patches for CVE-2019-7524
        #^#ea-apache24#^#2.4.39
          CVE-2019-0211: Apache HTTP Server privilege escalation from modules' scripts
   };
    $changelog =~ s/^[\s\n]+//mg;
    return $changelog;
} );

my $changelog_href = SSP::get_rpm_changelog_href();

ok( defined $changelog_href->{dovecot}->{version}, 'Checking for dovecot version' );
ok( $changelog_href->{dovecot}->{'CVE-2019-7524'}->{seen}, 'Checking dovecot for CVE-2019-7524' );
ok( defined $changelog_href->{openssl}->{version}, 'Checking for openssl version' );
ok( $changelog_href->{openssl}->{'CVE-2014-0224'}->{seen}, 'Checking openssl for CVE-2014-0224' );
ok( $changelog_href->{openssl}->{'CVE-2014-0160'}->{seen}, 'Checking openssl for CVE-2014-0160' );
ok( defined $changelog_href->{'ea-apache24'}->{version}, 'Checking ea-apache24 version' );
ok( $changelog_href->{'ea-apache24'}->{'CVE-2019-0211'}->{seen}, 'Checking ea-apache24 for CVE-2019-0211');
