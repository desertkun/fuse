/* DebuggerController.m: Routines for dealing with the Debugger Panel
   Copyright (c) 2002-2003 Fredrick Meunier

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

*/

#import "DebuggerController.h"
#import "DisplayOpenGLView.h"
#import "Emulator.h"

#include <config.h>

#include <libspectrum.h>
#include "debugger/debugger.h"
#include "event.h"
#include "fuse.h"
#include "machine.h"
#include "scld.h"
#include "settings.h"
#include "spectrum.h"
#include "ula.h"
#include "ui/ui.h"
#include "z80/z80.h"
#include "z80/z80_macros.h"
#include "zxcf.h"

static int activate_debugger( void );
static int deactivate_debugger( void );
static void add_event( gpointer data, gpointer user_data );

/* The top line of the current disassembly */
static libspectrum_word disassembly_top;

/* Is the debugger window active (as opposed to the debugger itself)? */
static int debugger_active;

@implementation DebuggerController

static DebuggerController *singleton = nil;
   
+ (DebuggerController *)singleton 
{  
  return singleton ? singleton : [[self alloc] init];
}

- (void)habdleCloseNotification: (NSNotificationCenter*)nc
{
    [nc addObserver:self
           selector:@selector(handleWillClose:)
               name:@"NSWindowWillCloseNotification"
             object:[self window]];
}
   
- (id)init
{
  NSNotificationCenter *nc;

  if ( singleton ) {
    [self dealloc];
  } else {
    [super init];
    self = [super initWithWindowNibName:@"Debugger"];
    singleton = self;

    nc = [NSNotificationCenter defaultCenter];
    
    [self performSelectorOnMainThread:@selector(habdleCloseNotification) withObject:nc waitUntilDone:YES];
    [self setWindowFrameAutosaveName:@"DebuggerWindow"];
  }

  return singleton;
}

- (void)awakeFromNib
{
  [events setTarget:self];
  [events setDoubleAction:@selector(eventsDoubleAction:)];

  [stack setTarget:self];
  [stack setDoubleAction:@selector(stackDoubleAction:)];
}

- (void)dealloc
{
  NSNotificationCenter *nc;

  nc = [NSNotificationCenter defaultCenter];
  [nc removeObserver:self];

  [super dealloc];
}

- (void)handleWillClose:(NSNotification *)note
{
  [breakpointsContents release];
  breakpointsContents = nil;
  [dissasemblyContents release];
  dissasemblyContents = nil;
  [stackContents release];
  stackContents = nil;
  [eventsContents release];
  eventsContents = nil;
  [memoryMapContents release];
  memoryMapContents = nil;

  debugger_run();
}

- (void)eventsDoubleAction:(id)sender
{
  int error, row;
  id record, value;
  
  row = [events clickedRow];

  if( row < 0 || row >= [eventsContents count] ) return;

  record = [eventsContents objectAtIndex:row];
  value  = [record valueForKey:@"time"];

  error = debugger_breakpoint_add_time( DEBUGGER_BREAKPOINT_TYPE_TIME,
                                  [value unsignedLongValue], 0,
                                  DEBUGGER_BREAKPOINT_LIFE_ONESHOT, NULL );
  if( error ) return;

  debugger_run();
}

- (void)stackDoubleAction:(id)sender
{
  libspectrum_word address, destination;
  int error, row;

  row = [stack clickedRow];

  if( row < 0 || row >= [stackContents count] ) return;

  address = SP + ( 19 - row ) * 2;

  destination =
    readbyte_internal( address ) + readbyte_internal( address + 1 ) *  0x100; 

  error = debugger_breakpoint_add_address( DEBUGGER_BREAKPOINT_TYPE_EXECUTE,
                                  memory_source_any, 0, destination, 0,
                                  DEBUGGER_BREAKPOINT_LIFE_ONESHOT, NULL );
  if( error ) return;

  debugger_run();
}

- (void)debugger_activate:(id)sender
{
  [[DisplayOpenGLView instance] pause];

  [singleton showWindow:nil];

  [continueButton setEnabled:YES];
  [breakButton setEnabled:NO];
  if( !debugger_active ) activate_debugger();

  [NSApp runModalForWindow:[self window]];
}

- (void)debugger_deactivate:(int)interruptable
{
  if( debugger_active ) deactivate_debugger();

  [continueButton setEnabled:!interruptable ? YES : NO];
  [breakButton setEnabled:interruptable ? YES : NO];
}
 
- (void)debugger_update_breakpoints
{
  /* Create the breakpoint list */
  NSString *condition;
  NSString *life;
  NSString *ignore;
  NSString *value;
  NSString *type;
  GSList *ptr;
  NSString *format_16_bit, *format_8_bit;
  
  if( debugger_output_base == 10 ) {
    format_16_bit = @"%5d";
    format_8_bit = @"%3d";
  } else {
    format_16_bit = @"0x%04X";
    format_8_bit = @"0x%02X";
  }
  
  if( breakpointsContents != nil ) {
    [breakpointsContents release];
    breakpointsContents = NULL;
  }
  
  breakpointsContents = [NSMutableArray arrayWithCapacity:5];
  
  [breakpointsContents retain];
  
  for( ptr = debugger_breakpoints; ptr; ptr = ptr->next ) {
    NSString *breakpoint_id;
    
    debugger_breakpoint *bp = ptr->data;
    
    breakpoint_id = [NSString stringWithFormat:@"%lu", (unsigned long)bp->id ];
    type = [NSString stringWithFormat:@"%s",
            debugger_breakpoint_type_text[ bp->type ] ];
    
    switch( bp->type ) {
      case DEBUGGER_BREAKPOINT_TYPE_EXECUTE:
      case DEBUGGER_BREAKPOINT_TYPE_READ:
      case DEBUGGER_BREAKPOINT_TYPE_WRITE:
        if( bp->value.address.page == -1 ) {
          value = [NSString stringWithFormat:format_16_bit, bp->value.address.offset ];
        } else {
          NSString *format_string = [NSString stringWithFormat:@"%%s:%s:%s", [format_16_bit UTF8String], [format_16_bit UTF8String]];
          value = [NSString stringWithFormat:format_string, memory_source_description( bp->value.address.source ),
                   bp->value.address.page, bp->value.address.offset ];
        }
        break;
        
      case DEBUGGER_BREAKPOINT_TYPE_PORT_READ:
      case DEBUGGER_BREAKPOINT_TYPE_PORT_WRITE:
        {
          NSString *format_string = [NSString stringWithFormat:@"%s:%s", [format_16_bit UTF8String], [format_16_bit UTF8String]];
          value = [NSString stringWithFormat:format_string, bp->value.port.mask, bp->value.port.port ];
        }
        break;
        
      case DEBUGGER_BREAKPOINT_TYPE_TIME:
        value = [NSString stringWithFormat:@"%5d", bp->value.time.tstates ];
        break;
        
      case DEBUGGER_BREAKPOINT_TYPE_EVENT:
        value = [NSString stringWithFormat:@"%s:%s", bp->value.event.type,
                 bp->value.event.detail ];
        break;
        
    }
    ignore = [NSString stringWithFormat:@"%lu", (unsigned long)bp->ignore ];
    life = [NSString stringWithFormat:@"%s",
            debugger_breakpoint_life_text[ bp->life ] ];
    if( bp->condition ) {
      char condition_cstring[80];
      debugger_expression_deparse( condition_cstring, 80, bp->condition );
      condition = @(condition_cstring);
    } else {
      condition = @"";
    }
    
    [breakpointsContents addObject:
     @{@"id": breakpoint_id,
       @"type": type,
       @"value": value,
       @"ignore": ignore,
       @"life": life,
       @"condition": condition}
     ];
  }
  
  [breakpoints reloadData];
}

- (void)debugger_update:(id)sender
{
  char buffer[40];
  NSString *format_16_bit, *format_8_bit;
  int capabilities;
  NSString *disassembly_address, *instruction;
  NSString *stack_address, *stack_value;
  libspectrum_word address;
  int source, page_num, writable, contended;
  libspectrum_word offset;
  size_t i, row;

  if( debugger_output_base == 10 ) {
    format_16_bit = @"%5d";
    format_8_bit = @"%3d";
  } else {
    format_16_bit = @"0x%04X";
    format_8_bit = @"0x%02X";
  }

  [PCText   setStringValue:[NSString stringWithFormat:format_16_bit, PC ]];
  [SPText   setStringValue:[NSString stringWithFormat:format_16_bit, SP ]];
  [AFText   setStringValue:[NSString stringWithFormat:format_16_bit, AF ]];
  [AF_Text  setStringValue:[NSString stringWithFormat:format_16_bit, AF_ ]];
  [BCText   setStringValue:[NSString stringWithFormat:format_16_bit, BC ]];
  [BC_Text  setStringValue:[NSString stringWithFormat:format_16_bit, BC_ ]];
  [DEText   setStringValue:[NSString stringWithFormat:format_16_bit, DE ]];
  [DE_Text  setStringValue:[NSString stringWithFormat:format_16_bit, DE_ ]];
  [HLText   setStringValue:[NSString stringWithFormat:format_16_bit, HL ]];
  [HL_Text  setStringValue:[NSString stringWithFormat:format_16_bit, HL_ ]];
  [IXText   setStringValue:[NSString stringWithFormat:format_16_bit, IX ]];
  [IYText   setStringValue:[NSString stringWithFormat:format_16_bit, IY ]];
  [IText    setStringValue:[NSString stringWithFormat:format_8_bit,  I ]];
  [RText    setStringValue:[NSString stringWithFormat:format_8_bit,  (R & 0x7f) | (R7 & 0x80) ]];
  [tStates  setStringValue:[NSString stringWithFormat:@"%5d",        tstates ]];
  [IMText   setIntValue:IM];
  [IFF1Text setIntValue:IFF1];
  [IFF2Text setIntValue:IFF2];

  for( i = 0; i < 8; i++ ) buffer[i] = ( F & ( 0x80 >> i ) ) ? '1' : '0';
  buffer[8] = '\0';

  [flags setStringValue:@(buffer)];

  capabilities = libspectrum_machine_capabilities( machine_current->machine );

  [ULAText setStringValue:
                  [NSString stringWithFormat:format_8_bit,ula_last_byte()]];

  if( capabilities & LIBSPECTRUM_MACHINE_CAPABILITY_AY ) {
    [AYText setStringValue:
                    [NSString stringWithFormat:format_8_bit,
                              machine_current->ay.current_register]];
  } else {
    [AYText setStringValue:@"NA"];
  }

  if( capabilities & LIBSPECTRUM_MACHINE_CAPABILITY_128_MEMORY ) {
    [mem128 setStringValue:
                    [NSString stringWithFormat:format_8_bit,
                              machine_current->ram.last_byte]];
  } else {
    [mem128 setStringValue:@"NA"];
  }

  if( capabilities & LIBSPECTRUM_MACHINE_CAPABILITY_PLUS3_MEMORY ) {
    [memPlus3 setStringValue:
                    [NSString stringWithFormat:format_8_bit,
                              machine_current->ram.last_byte2]];
  } else {
    [memPlus3 setStringValue:@"NA"];
  }

  if( capabilities & LIBSPECTRUM_MACHINE_CAPABILITY_TIMEX_VIDEO  ||
      capabilities & LIBSPECTRUM_MACHINE_CAPABILITY_TIMEX_MEMORY ||
      capabilities & LIBSPECTRUM_MACHINE_CAPABILITY_SE_MEMORY ) {
    [timexDEC setStringValue:
                  [NSString stringWithFormat:format_8_bit,scld_last_dec.byte]];
  } else {
    [timexDEC setStringValue:@"NA"];
  }

  if( capabilities & LIBSPECTRUM_MACHINE_CAPABILITY_TIMEX_MEMORY ||
      capabilities & LIBSPECTRUM_MACHINE_CAPABILITY_SE_MEMORY       ) {
    [timexHSR setStringValue:
                  [NSString stringWithFormat:format_8_bit,scld_last_hsr]];
  } else {
    [timexHSR setStringValue:@"NA"];
  }

  if( settings_current.zxcf_active ) {
    [zxcf setStringValue:
                  [NSString stringWithFormat:format_8_bit,zxcf_last_memctl()]];
  } else {
    [zxcf setStringValue:@"NA"];
  }

  [z80Halted setIntValue:z80.halted];
  
  [self debugger_update_breakpoints];

  /* Put some disassembly in */
  if( dissasemblyContents != nil ) {
    [dissasemblyContents release];
    dissasemblyContents = nil;
  }

  dissasemblyContents = [NSMutableArray arrayWithCapacity:25];

  [dissasemblyContents retain];

  for( i = 0, address = disassembly_top; i < 20; i++ ) {
    
    size_t length;

    disassembly_address = [NSString stringWithFormat:format_16_bit, address ];
    debugger_disassemble( buffer, 40, &length, address );
    instruction = @(buffer);
    address += length;

    [dissasemblyContents addObject:
      @{@"address": disassembly_address,
        @"instruction": instruction}
    ];
  }

  [dissasembly reloadData];

  /* And the stack display */
  if( stackContents != nil ) {
    [stackContents release];
    stackContents = nil;
  }

  stackContents = [NSMutableArray arrayWithCapacity:25];

  [stackContents retain];

  for( i = 0, address = SP + 38; i < 20; i++, address -= 2 ) {
    
    libspectrum_word contents = readbyte_internal( address ) +
                    0x100 * readbyte_internal( address + 1 );

    stack_address = [NSString stringWithFormat:format_16_bit, address ];
    stack_value = [NSString stringWithFormat:format_16_bit, contents ];

    [stackContents addObject:
      @{@"address": stack_address,
        @"value": stack_value}
    ];
  }

  [stack reloadData];

  /* And the events display */
  if( eventsContents != nil ) {
    [eventsContents release];
    eventsContents = nil;
  }

  eventsContents = [NSMutableArray arrayWithCapacity:25];

  [eventsContents retain];

  event_foreach( add_event, NULL );

  [events reloadData];

  /* And the memory map display */
  if( memoryMapContents != nil ) {
    [memoryMapContents release];
    memoryMapContents = nil;
  }

  memoryMapContents = [NSMutableArray arrayWithCapacity:8];

  [memoryMapContents retain];

  source = page_num = writable = contended = -1;
  offset = 0;
  row = 0;
  
  for( i = 0; i < MEMORY_PAGES_IN_64K; i++ ) {
    memory_page *page = &memory_map_read[i];

    if( page->source != source ||
       page->page_num != page_num ||
       page->offset != offset ||
       page->writable != writable ||
       page->contended != contended ) {

      NSString *memory_map_address = [NSString stringWithFormat:format_16_bit, i*MEMORY_PAGE_SIZE ];
      NSString *memory_map_type = [NSString stringWithFormat:@"%s", memory_source_description( page->source )];
      NSNumber *memory_map_page = @(memory_map_read[i].page_num);
      NSString *memory_map_writeable = [NSString stringWithFormat:@"%s", page->writable ? "Y" : "N" ];
      NSString *memory_map_contended = [NSString stringWithFormat:@"%s", page->contended ? "Y" : "N" ];

      [memoryMapContents addObject:
            @{@"address": memory_map_address,
              @"type": memory_map_type,
              @"page": memory_map_page,
              @"writeable": memory_map_writeable,
              @"contended": memory_map_contended}
       ];
      
      row++;
      
      source = page->source;
      page_num = page->page_num;
      writable = page->writable;
      contended = page->contended;
      offset = page->offset;
    }
    
    /* We expect the next page to have an increased offset */
    offset += MEMORY_PAGE_SIZE;
  }

  [memoryMap reloadData];
}

- (void)add_event:(event_t *)ptr
{
  /* Skip events which have been removed */
  if( ptr->type == event_type_null ) return;
  
  NSNumber *event_time = @(ptr->tstates);
  NSString *event_type = @(event_name( ptr->type ));

  [eventsContents addObject:@{@"time": event_time, @"type": event_type}];
}

- (void)debugger_disassemble:(libspectrum_word)address
{
  disassembly_top = address;
}

- (IBAction)debugger_cmd_evaluate:(id)sender
{
  debugger_command_evaluate( [[entry stringValue] UTF8String] );
}

- (IBAction)debugger_done_step:(id)sender
{
  debugger_step();
}

- (IBAction)debugger_done_continue:(id)sender
{
  debugger_run();
}

- (IBAction)debugger_break:(id)sender
{
  debugger_mode = DEBUGGER_MODE_HALTED;
  [continueButton setEnabled:YES];
  [breakButton setEnabled:NO];
}

- (int)numberOfRowsInTableView:(NSTableView *)table
{
  switch( [table tag] ) {
  case 0:
    if( dissasemblyContents != nil )
      return [dissasemblyContents count];
    break;
  case 1:
    if( stackContents != nil )
      return [stackContents count];
    break;
  case 2:
    if( breakpointsContents != nil )
      return [breakpointsContents count];
    break;
  case 3:
    if( eventsContents != nil )
      return [eventsContents count];
    break;
  case 4:
    if( memoryMapContents != nil )
      return [memoryMapContents count];
    break;
  default:
    break;
  }

  return 0;
}

- (id)tableView:(NSTableView *)table objectValueForTableColumn:(NSTableColumn *)col row:(int)row
{
  id record, value;

  switch( [table tag] ) {
  case 0:
    if(row < 0 || row > [dissasemblyContents count]) return nil;
    record = [dissasemblyContents objectAtIndex:row];
    value = [record valueForKey:[col identifier]];
    return value;
    break;
  case 1:
    if(row < 0 || row > [stackContents count]) return nil;
    record = [stackContents objectAtIndex:row];
    value = [record valueForKey:[col identifier]];
    return value;
    break;
  case 2:
    if(row < 0 || row > [breakpointsContents count]) return nil;
    record = [breakpointsContents objectAtIndex:row];
    value = [record valueForKey:[col identifier]];
    return value;
    break;
  case 3:
    if(row < 0 || row > [eventsContents count]) return nil;
    record = [eventsContents objectAtIndex:row];
    value = [record valueForKey:[col identifier]];
    return value;
    break;
  case 4:
    if(row < 0 || row > [memoryMapContents count]) return nil;
    record = [memoryMapContents objectAtIndex:row];
    value = [record valueForKey:[col identifier]];
    return value;
    break;
  default:
    break;
  }

  return nil;
}

- (BOOL)tableView:(NSTableView *)aTableView shouldSelectRow:(int)rowIndex
{
  return NO;
}

@end

int
ui_debugger_activate( void )
{
  [[Emulator instance] debuggerActivate];

  return 0;
}

int
ui_debugger_deactivate( int interruptable )
{
  [[DebuggerController singleton] debugger_deactivate:interruptable];

  return 0;
}

/* Update the debugger's display */
int
ui_debugger_update( void )
{
  [[DebuggerController singleton] debugger_update:nil];

  return 0;
}

void
ui_breakpoints_updated( void )
{
  [[DebuggerController singleton] debugger_update_breakpoints];
}

/* Set the disassembly to start at 'address' */
int
ui_debugger_disassemble( libspectrum_word address )
{
  [[DebuggerController singleton] debugger_disassemble:address];

  return 0;
}

static int
activate_debugger( void )
{
  debugger_active = 1;

  disassembly_top = PC;
  ui_debugger_update();

  return 0;
}

static int
deactivate_debugger( void )
{ 
  [NSApp stopModal];
  debugger_active = 0;
  [[DisplayOpenGLView instance] unpause];
  return 0;
}

static void
add_event( gpointer data, gpointer user_data )
{
  [[DebuggerController singleton] add_event:(event_t*) data];
}
