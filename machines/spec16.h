/* spec16.h: Spectrum 16K specific routines
   Copyright (c) 1999-2003 Philip Kendall

   $Id$

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

   Author contact information:

   E-mail: pak21-fuse@srcf.ucam.org
   Postal address: 15 Crescent Road, Wokingham, Berks, RG40 2DB, England

*/

#ifndef FUSE_SPEC16_H
#define FUSE_SPEC16_H

#include <libspectrum.h>

#ifndef FUSE_MACHINE_H
#include "machine.h"
#endif			/* #ifndef FUSE_MACHINE_H */

libspectrum_byte spec16_readbyte( libspectrum_word address );
libspectrum_byte spec16_readbyte_internal( libspectrum_word address );
void spec16_writebyte( libspectrum_word address, libspectrum_byte b );
void spec16_writebyte_internal( libspectrum_word address, libspectrum_byte b );

int spec16_init( fuse_machine_info *machine );
int spec16_reset( void );

#endif			/* #ifndef FUSE_SPEC16_H */