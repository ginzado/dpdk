#!/usr/bin/perl -w

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 Ginzado Co., Ltd.

use strict;
use lib "/usr/lib/nagios/plugins";
use lib "/usr/local/nagios/libexec";
use utils qw($TIMEOUT %ERRORS &print_revision &support &usage);
use Getopt::Long qw(:config no_ignore_case);

sub print_usage ();
sub print_version ();
sub print_help ();

my $plugin_revision = '0.1';
my $warning = 4;
my $critical = 1;
my $version;
my $help;

my $prog_dir;
my $prog_name = $0;
if ($0 =~ s/^(.*?)[\/\\]([^\/\\]+)$//) {
	$prog_dir = $1;
	$prog_name = $2;
}

my $good_options = GetOptions (
	"w|warning=s"		=> \$warning,
	"c|critical=s"		=> \$critical,
	"v|version"		=> \$version,
	"help"			=> \$help,
);

print_version() if $version;
print_help() if $help;
print_help() unless $good_options;

my $res1 = `gpwstats 2> /dev/null | grep gpwstats.ul_rx_bpdus | awk '{print \$2}'`;
$res1 = 0 if $res1 eq '';
sleep(5);
my $res2 = `gpwstats 2> /dev/null | grep gpwstats.ul_rx_bpdus | awk '{print \$2}'`;
$res2 = 0 if $res2 eq '';

my $thing = ($res2 - $res1);
if ($thing < $critical) {
	print "CRITICAL: $thing";
	exit $ERRORS{'CRITICAL'};
} elsif ($thing < $warning) {
	print "WARNING: $thing";
	exit $ERRORS{'WARNING'};
}
print "OK - $thing";
exit $ERRORS{'OK'};

sub print_version()
{
	print "$prog_name $plugin_revision\n";
	exit $ERRORS{'OK'};
}

sub print_help()
{
	print "./$prog_name [--warning|-w <value>] [--critical|-c <value]
./$prog_name --version|-v
./$prog_name --help

	--warning, -w	Override the default warning value of $warning

	--critical, -c 	Override the default critical value of $critical

	--version, -v	Print the version of this plugin

	--help 		Print this
";
	exit $ERRORS{'OK'};
}

