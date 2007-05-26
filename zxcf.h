/* zxcf.h: ZXCF interface routines
   Copyright (c) 2003-2004 Garry Lancaster,
		 2004 Philip Kendall

   $Id$

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

   Author contact information:

   E-mail: Philip Kendall <philip-fuse@shadowmagic.org.uk>

*/

#ifndef FUSE_ZXCF_H
#define FUSE_ZXCF_H

#include <libspectrum.h>
#include "periph.h"

extern const periph_t zxcf_peripherals[];
extern const size_t zxcf_peripherals_count;

int zxcf_init( void );
int zxcf_end( void );
void zxcf_reset( void );
int zxcf_insert( const char *filename );
int zxcf_commit();
int zxcf_eject( void );
void zxcf_memory_map( void );
libspectrum_byte zxcf_last_memctl( void );

int zxcf_from_snapshot( libspectrum_snap *snap );
int zxcf_to_snapshot( libspectrum_snap *snap );

#endif			/* #ifndef FUSE_ZXCF_H */

