/* specplus3.h: Spectrum +2A/+3 specific routines
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

#ifndef FUSE_SPECPLUS3_H
#define FUSE_SPECPLUS3_H

#include <libspectrum.h>

#ifndef FUSE_MACHINE_H
#include "machine.h"
#endif			/* #ifndef FUSE_MACHINE_H */

#ifdef HAVE_765_H
#include <limits.h>	/* Needed to get PATH_MAX */
#include <sys/types.h>

#include <765.h>
#endif			/* #ifdef HAVE_765_H */

libspectrum_byte specplus3_unattached_port( void );

libspectrum_byte specplus3_readbyte( libspectrum_word address );
libspectrum_byte specplus3_readbyte_internal( libspectrum_word address );
libspectrum_byte specplus3_read_screen_memory( libspectrum_word offset );
void specplus3_writebyte( libspectrum_word address, libspectrum_byte b );
void specplus3_writebyte_internal( libspectrum_word address,
				   libspectrum_byte b );

libspectrum_dword specplus3_contend_memory( libspectrum_word address );
libspectrum_dword specplus3_contend_port( libspectrum_word address );
libspectrum_byte specplus3_contend_delay( libspectrum_dword time );

int specplus3_init( fuse_machine_info *machine );
int specplus3_reset(void);

int specplus3_plus2a_common_reset( void );

void specplus3_memoryport_write( libspectrum_word port, libspectrum_byte b );
void specplus3_memoryport2_write( libspectrum_word port, libspectrum_byte b );

/* We need these outside the HAVE_765_H guards as they're also used
   for identifying the TRDOS drives */
typedef enum specplus3_drive_number {
  SPECPLUS3_DRIVE_A = 0,	/* First drive must be number zero */
  SPECPLUS3_DRIVE_B,
} specplus3_drive_number;

#ifdef HAVE_765_H
/* The +3's drives */

typedef struct specplus3_drive_t {
  int fd;			/* The file descriptor for the
				   temporary file we are using for
				   this disk */
  char filename[ PATH_MAX ];	/* And the name of the temporary file */

  FDRV_PTR drive;		/* The lib765 structure for this drive */
} specplus3_drive_t;

int specplus3_disk_present( specplus3_drive_number which );
int specplus3_disk_insert( specplus3_drive_number which,
			   const char *filename );
int specplus3_disk_eject( specplus3_drive_number which, int save );
int specplus3_disk_write( specplus3_drive_number which, const char *filename );
#endif			/* #ifdef HAVE_765_H */

#endif			/* #ifndef FUSE_SPECPLUS3_H */