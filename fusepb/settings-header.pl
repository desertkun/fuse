#!/usr/bin/perl -w

# settings-header.pl: generate settings.h from settings.dat
# Copyright (c) 2002-2003 Philip Kendall, Fredrick Meunier

# $Id$

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 49 Temple Place, Suite 330, Boston, MA 02111-1307 USA

# Author contact information:

# E-mail: pak21-fuse@srcf.ucam.org

use strict;

use lib 'perl';

use Fuse;

my %options;

while(<>) {

    next if /^\s*$/;
    next if /^\s*#/;

    chomp;

    my( $name, $type, $default, $short, $commandline, $configfile ) =
	split /\s*,\s*/;

    if( not defined $commandline ) {
	$commandline = $name;
	$commandline =~ s/_/-/g;
    }

    if( not defined $configfile ) {
	$configfile = $commandline;
	$configfile =~ s/-//g;
    }

    $options{$name} = { type => $type, default => $default, short => $short,
			commandline => $commandline,
			configfile => $configfile };
}

print Fuse::GPL( 'settings.h: Handling configuration settings',
		 'Copyright (c) 2001-2003 Philip Kendall, Fredrick Meunier' );

print << 'CODE';

#include <config.h>

#include <sys/types.h>

#ifndef FUSE_SETTINGS_H
#define FUSE_SETTINGS_H

typedef struct settings_cocoa settings_cocoa;

typedef struct settings_info {

CODE

foreach my $name ( sort keys %options ) {

    my $type = $options{$name}->{type};

    if( $type eq 'boolean' or $type eq 'numeric' ) {
	print "   int $name;\n";
    } elsif( $type eq 'string' ) {
	print "  char *$name;\n";
    } elsif( $type eq 'nsarray' ) {
	# Do nothing
    } elsif( $type eq 'null' ) {
	# Do nothing
    } else {
	die "Unknown setting type `$type'";
    }

}

print << 'CODE';

  settings_cocoa *cocoa;

  int show_help;
  int show_version;

} settings_info;

extern settings_info settings_current;
extern settings_info settings_default;

int settings_init( int *first_arg, int argc, char **argv );
void settings_defaults( settings_info *settings );
void settings_copy( settings_info *dest, settings_info *src );

#define SETTINGS_ROM_COUNT 32
extern const char *settings_rom_name[ SETTINGS_ROM_COUNT ];
char **settings_get_rom_setting( settings_info *settings, size_t which,
				 int is_peripheral );

void settings_set_string( char **string_setting, const char *value );

int settings_free( settings_info *settings );

int read_config_file( settings_info *settings );
int settings_write_config( settings_info *settings );

void settings_register_startup( void );

#endif				/* #ifndef FUSE_SETTINGS_H */
CODE
