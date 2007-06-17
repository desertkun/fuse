/* plusd.c: Routines for handling the +D interface
   Copyright (c) 1999-2007 Stuart Brady, Fredrick Meunier, Philip Kendall,
   Dmitry Sanarin, Darren Salt

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

   Philip: philip-fuse@shadowmagic.org.uk

   Stuart: sdbrady@ntlworld.com

*/

#include <config.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>            /* Needed for strncasecmp() on QNX6 */
#endif                          /* #ifdef HAVE_STRINGS_H */
#include <limits.h>
#include <sys/stat.h>

#include <libdsk.h>

#include <libspectrum.h>

#include "compat.h"
#include "event.h"
#include "machine.h"
#include "module.h"
#include "plusd.h"
#include "printer.h"
#include "settings.h"
#include "ui/ui.h"
#include "utils.h"
#include "wd1770.h"
#include "z80/z80.h"

int plusd_available = 0;
int plusd_active = 0;
int plusd_index_pulse = 0;

wd1770_fdc plusd_fdc;
wd1770_drive plusd_drives[ PLUSD_NUM_DRIVES ];

static const char *plusd_template = "fuse.plusd.XXXXXX";

static void plusd_reset( int hard_reset );
static void plusd_memory_map( void );
static void plusd_from_snapshot( libspectrum_snap *snap );
static void plusd_to_snapshot( libspectrum_snap *snap );

static module_info_t plusd_module_info = {

  plusd_reset,
  plusd_memory_map,
  plusd_from_snapshot,
  plusd_to_snapshot,

};

void
plusd_page( void )
{
  plusd_active = 1;
  machine_current->ram.romcs = 1;
  machine_current->memory_map();
}

void
plusd_unpage( void )
{
  plusd_active = 0;
  machine_current->ram.romcs = 0;
  machine_current->memory_map();
}

static void
plusd_memory_map( void )
{
  if( !plusd_active ) return;

  memory_map_read[ 0 ] = memory_map_write[ 0 ] = memory_map_romcs[ 0 ];
  memory_map_read[ 1 ] = memory_map_write[ 1 ] = memory_map_ram[ 16 * 2 ];
}

void
plusd_set_cmdint( wd1770_fdc *f )
{
  z80_interrupt();
}

const periph_t plusd_peripherals[] = {
  /* ---- ---- 1110 0011 */
  { 0x00ff, 0x00e3, plusd_sr_read, plusd_cr_write },
  /* ---- ---- 1110 1011 */
  { 0x00ff, 0x00eb, plusd_tr_read, plusd_tr_write },
  /* ---- ---- 1111 0011 */
  { 0x00ff, 0x00f3, plusd_sec_read, plusd_sec_write },
  /* ---- ---- 1111 1011 */
  { 0x00ff, 0x00fb, plusd_dr_read, plusd_dr_write },

  /* ---- ---- 1110 1111 */
  { 0x00ff, 0x00ef, NULL, plusd_cn_write },
  /* ---- ---- 1110 0111 */
  { 0x00ff, 0x00e7, plusd_mem_read, plusd_mem_write },
  /* 0000 0000 1111 0111 */
  { 0x00ff, 0x00f7, plusd_printer_read, printer_parallel_write },
};

const size_t plusd_peripherals_count =
  sizeof( plusd_peripherals ) / sizeof( periph_t );

int
plusd_init( void )
{
  int i;
  wd1770_drive *d;

  plusd_fdc.current_drive = &plusd_drives[ 0 ];

  for( i = 0; i < PLUSD_NUM_DRIVES; i++ ) {
    d = &plusd_drives[ i ];

    d->disk = NULL;
    d->filename[0] = '\0';
  }

  plusd_fdc.set_cmdint = &plusd_set_cmdint;
  plusd_fdc.reset_cmdint = NULL;
  plusd_fdc.set_datarq = NULL;
  plusd_fdc.reset_datarq = NULL;
  plusd_fdc.iface = NULL;

  plusd_fdc.rates[ 0 ] = 6;
  plusd_fdc.rates[ 1 ] = 12;
  plusd_fdc.rates[ 2 ] = 2;
  plusd_fdc.rates[ 3 ] = 3;

  module_register( &plusd_module_info );

  return 0;
}

static void
plusd_reset( int hard_reset )
{
  int i;
  wd1770_drive *d;
  wd1770_fdc *f = &plusd_fdc;

  plusd_available = 0;

  if( !periph_plusd_active )
    return;

  machine_load_rom_bank( memory_map_romcs, 0, 0,
			 settings_default.rom_plusd,
			 settings_current.rom_plusd, 0x2000 );

  memory_map_romcs[0].source = MEMORY_SOURCE_PERIPHERAL;

  machine_current->ram.romcs = 0;

  memory_map_romcs[ 0 ].writable = 0;
  memory_map_romcs[ 1 ].writable = 0;
  memory_map_ram[ 16 * 2 ].writable = 1;

  plusd_available = 1;
  plusd_active = 0;
  plusd_index_pulse = 0;

  if( hard_reset ) {
    for( i = 0; i < 8192; i++ ) {
      memory_map_ram[ 16 * 2 ].page[ i ] = 0;
    }
  }

  f->spin_cycles = 0;
  f->direction = 0;

  f->state = wd1770_state_none;
  f->status_type = wd1770_status_type1;

  f->status_register = 0;
  f->track_register = 0;
  f->sector_register = 0;
  f->data_register = 0;

  for( i = 0; i < PLUSD_NUM_DRIVES; i++ ) {
    d = &plusd_drives[ i ];

    d->index_pulse = 0;
    d->index_interrupt = 0;
    d->track = 0;
    d->side = 0;
  }

  f->status_register |= WD1770_SR_LOST; /* track 0 */

  /* We can eject disks only if they are currently present */
  ui_menu_activate( UI_MENU_ITEM_MEDIA_DISK_PLUSD_1_EJECT,
		    !!plusd_drives[ PLUSD_DRIVE_1 ].disk );
  ui_menu_activate( UI_MENU_ITEM_MEDIA_DISK_PLUSD_2_EJECT,
		    !!plusd_drives[ PLUSD_DRIVE_2 ].disk );

  plusd_fdc.current_drive = &plusd_drives[ 0 ];
  machine_current->memory_map();
  plusd_event_index( 0 );

  ui_statusbar_update( UI_STATUSBAR_ITEM_DISK, UI_STATUSBAR_STATE_INACTIVE );
}

void
plusd_end( void )
{
  plusd_available = 0;
}

libspectrum_byte
plusd_sr_read( libspectrum_word port GCC_UNUSED, int *attached )
{
  *attached = 1;
  return wd1770_sr_read( &plusd_fdc );
}

void
plusd_cr_write( libspectrum_word port GCC_UNUSED, libspectrum_byte b )
{
  wd1770_cr_write( &plusd_fdc, b );
}

libspectrum_byte
plusd_tr_read( libspectrum_word port GCC_UNUSED, int *attached )
{
  *attached = 1;
  return wd1770_tr_read( &plusd_fdc );
}

void
plusd_tr_write( libspectrum_word port GCC_UNUSED, libspectrum_byte b )
{
  wd1770_tr_write( &plusd_fdc, b );
}

libspectrum_byte
plusd_sec_read( libspectrum_word port GCC_UNUSED, int *attached )
{
  *attached = 1;
  return wd1770_sec_read( &plusd_fdc );
}

void
plusd_sec_write( libspectrum_word port GCC_UNUSED, libspectrum_byte b )
{
  wd1770_sec_write( &plusd_fdc, b );
}

libspectrum_byte
plusd_dr_read( libspectrum_word port GCC_UNUSED, int *attached )
{
  *attached = 1;
  return wd1770_dr_read( &plusd_fdc );
}

void
plusd_dr_write( libspectrum_word port GCC_UNUSED, libspectrum_byte b )
{
  wd1770_dr_write( &plusd_fdc, b );
}

void
plusd_cn_write( libspectrum_word port GCC_UNUSED, libspectrum_byte b )
{
  int drive, side;
  int i;

  drive = ( b & 0x03 ) == 2 ? 1 : 0;
  side = ( b & 0x80 ) ? 1 : 0;

  /* TODO: set current_drive to NULL when bits 0 and 1 of b are '00' or '11' */
  plusd_fdc.current_drive = &plusd_drives[ drive ];

  for( i = 0; i < PLUSD_NUM_DRIVES; i++ ) {
    plusd_drives[ i ].side = side;
  }

  printer_parallel_strobe_write( b & 0x40 );
}

libspectrum_byte
plusd_mem_read( libspectrum_word port GCC_UNUSED, int *attached )
{
  plusd_page();
  return 0;
}

void
plusd_mem_write( libspectrum_word port GCC_UNUSED, libspectrum_byte b )
{
  plusd_unpage();
}

libspectrum_byte
plusd_printer_read( libspectrum_word port GCC_UNUSED, int *attached )
{
  *attached = 1;

  /* bit 7 = busy. other bits high? */

  if(!settings_current.printer)
    return(0xff); /* no printer attached */

  return(0x7f);   /* never busy */
}

int
plusd_disk_insert_default_autoload( plusd_drive_number which,
				    const char *filename )
{
  return plusd_disk_insert( which, filename, settings_current.auto_load );
}

int
plusd_disk_insert( plusd_drive_number which, const char *filename,
		   int autoload )
{
  int fd, error;
  char tempfilename[ PATH_MAX ];
  int israw = 0;
  dsk_format_t fmt;
  wd1770_drive *d;
  int l;

  if( which >= PLUSD_NUM_DRIVES ) {
    ui_error( UI_ERROR_ERROR, "plusd_disk_insert: unknown drive %d",
	      which );
    fuse_abort();
  }

  d = &plusd_drives[ which ];

  /* Eject any disk already in the drive */
  if( d->disk ) {
    /* Abort the insert if we want to keep the current disk */
    if( plusd_disk_eject( which, 0 ) ) return 0;
  }

  /* Make a temporary copy of the disk file */
  error = utils_make_temp_file( &fd, tempfilename, filename, plusd_template );
  if( error ) return error;
  strcpy( d->filename, tempfilename );

  /* Determine the disk image format */
  l = strlen( filename );
  if( l >= 5 ) {
    if( !strcmp( filename + ( l - 4 ), ".dsk" ) ||
	!strcmp( filename + ( l - 4 ), ".mgt" )    ) {
      israw = 1;
      fmt = FMT_800K;
    } else if( !strcmp( filename + ( l - 4 ), ".img" ) ) {
      israw = 1;
      fmt = FMT_MGT800;
    }
  }

  /* And now insert the disk */
  if( israw ) {

    /* If the "logical" driver is not available, try the "raw" driver (unless
     * we're using FMT_MGT800, for which the raw driver will not work */
    if( dsk_open( &d->disk, tempfilename, "logical", NULL ) != DSK_ERR_OK &&
	( fmt == FMT_MGT800 ||
	  dsk_open( &d->disk, tempfilename, "raw", NULL ) != DSK_ERR_OK ) ) {
      ui_error( UI_ERROR_ERROR, "Failed to open disk image" );
      return 1;
    }

    if( dg_stdformat( &d->geom, fmt, NULL, NULL ) != DSK_ERR_OK ) {
      ui_error( UI_ERROR_ERROR, "Failed to set geometry for disk" );
      dsk_close( &d->disk );
      return 1;
    }

  } else {

    if( dsk_open( &d->disk, tempfilename, NULL, NULL ) != DSK_ERR_OK ) {
      ui_error( UI_ERROR_ERROR, "Failed to open disk image" );
      return 1;
    }

    if( dsk_getgeom( d->disk, &d->geom ) != DSK_ERR_OK ) {
      ui_error( UI_ERROR_ERROR, "Failed to determine geometry for disk" );
      dsk_close( &d->disk );
      return 1;
    }

  }

  /* Set the 'eject' item active */
  switch( which ) {
  case PLUSD_DRIVE_1:
    ui_menu_activate( UI_MENU_ITEM_MEDIA_DISK_PLUSD_1_EJECT, 1 );
    break;
  case PLUSD_DRIVE_2:
    ui_menu_activate( UI_MENU_ITEM_MEDIA_DISK_PLUSD_2_EJECT, 1 );
    break;
  }

  if( autoload ) {
    /* XXX */
  }

  return 0;
}

int
plusd_disk_eject( plusd_drive_number which, int write )
{
  wd1770_drive *d;

  if( which >= PLUSD_NUM_DRIVES )
    return 1;

  d = &plusd_drives[ which ];

  if( !d->disk )
    return 0;

  if( write ) {

    if( ui_plusd_disk_write( which ) ) return 1;

  } else {

    if( dsk_dirty( plusd_drives[which].disk ) ) {

      ui_confirm_save_t confirm = ui_confirm_save(
	"Disk has been modified.\nDo you want to save it?"
      );

      switch( confirm ) {

      case UI_CONFIRM_SAVE_SAVE:
	if( ui_plusd_disk_write( which ) ) return 1;
	break;

      case UI_CONFIRM_SAVE_DONTSAVE: break;
      case UI_CONFIRM_SAVE_CANCEL: return 1;

      }
    }
  }

  dsk_close( &d->disk );
  unlink( d->filename );

  /* Set the 'eject' item inactive */
  switch( which ) {
  case PLUSD_DRIVE_1:
    ui_menu_activate( UI_MENU_ITEM_MEDIA_DISK_PLUSD_1_EJECT, 0 );
    break;
  case PLUSD_DRIVE_2:
    ui_menu_activate( UI_MENU_ITEM_MEDIA_DISK_PLUSD_2_EJECT, 0 );
    break;
  }
  return 0;
}

int
plusd_disk_write( plusd_drive_number which, const char *filename )
{
  wd1770_drive *d = &plusd_drives[ which ];
  utils_file file;
  FILE *f;
  int error;
  size_t bytes_written;

  dsk_close( &d->disk );

  f = fopen( filename, "wb" );
  if( !f ) {
    ui_error( UI_ERROR_ERROR, "couldn't open '%s' for writing: %s", filename,
	      strerror( errno ) );
  }

  error = utils_read_file( d->filename, &file );
  if( error ) { fclose( f ); return error; }

  bytes_written = fwrite( file.buffer, 1, file.length, f );
  if( bytes_written != file.length ) {
    ui_error( UI_ERROR_ERROR, "could write only %lu of %lu bytes to '%s'",
	      (unsigned long)bytes_written, (unsigned long)file.length,
	      filename );
    utils_close_file( &file ); fclose( f );
  }

  error = utils_close_file( &file ); if( error ) { fclose( f ); return error; }

  if( fclose( f ) ) {
    ui_error( UI_ERROR_ERROR, "error closing '%s': %s", filename,
	      strerror( errno ) );
    return 1;
  }

  return 0;
}

int
plusd_event_cmd_done( libspectrum_dword last_tstates )
{
  plusd_fdc.status_register &= ~WD1770_SR_BUSY;
  return 0;
}

int
plusd_event_index( libspectrum_dword last_tstates )
{
  int error;
  int next_tstates;
  int i;

  plusd_index_pulse = !plusd_index_pulse;
  for( i = 0; i < PLUSD_NUM_DRIVES; i++ ) {
    wd1770_drive *d = &plusd_drives[ i ];

    d->index_pulse = plusd_index_pulse;
    if( !plusd_index_pulse && d->index_interrupt ) {
      wd1770_set_cmdint( &plusd_fdc );
      d->index_interrupt = 0;
    }
  }
  next_tstates = ( plusd_index_pulse ? 10 : 190 ) *
    machine_current->timings.processor_speed / 1000;
  error = event_add( last_tstates + next_tstates, EVENT_TYPE_PLUSD_INDEX );
  if( error )
    return error;
  return 0;
}

static void
plusd_from_snapshot( libspectrum_snap *snap )
{
  /* XXX */
}

static void
plusd_to_snapshot( libspectrum_snap *snap )
{
  /* XXX */
}