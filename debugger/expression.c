/* expression.c: A numeric expression
   Copyright (c) 2003 Philip Kendall

   $Id$

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

   Author contact information:

   E-mail: pak21-fuse@srcf.ucam.org
   Postal address: 15 Crescent Road, Wokingham, Berks, RG40 2DB, England

*/

#include <config.h>

#include <stdlib.h>

#include "debugger_internals.h"
#include "ui/ui.h"

typedef enum debugger_expression_type {

  DEBUGGER_EXPRESSION_TYPE_INTEGER,
  DEBUGGER_EXPRESSION_TYPE_REGISTER,

} debugger_expression_type;

struct debugger_expression {

  debugger_expression_type type;

  union {
    int integer;
    int reg;
  } types;

};

debugger_expression*
debugger_expression_new_number( int number )
{
  debugger_expression *exp;

  exp = malloc( sizeof( debugger_expression ) );
  if( !exp ) {
    ui_error( UI_ERROR_ERROR, "out of memory at %s:%d", __FILE__, __LINE__ );
    return NULL;
  }

  exp->type = DEBUGGER_EXPRESSION_TYPE_INTEGER;
  exp->types.integer = number;

  return exp;
}

debugger_expression*
debugger_expression_new_register( int which )
{
  debugger_expression *exp;

  exp = malloc( sizeof( debugger_expression ) );
  if( !exp ) {
    ui_error( UI_ERROR_ERROR, "out of memory at %s:%d", __FILE__, __LINE__ );
    return NULL;
  }

  exp->type = DEBUGGER_EXPRESSION_TYPE_REGISTER;
  exp->types.reg = which;

  return exp;
}

void
debugger_expression_delete( debugger_expression *exp )
{
  free( exp );
}

int
debugger_expression_evaluate( debugger_expression *exp )
{
  switch( exp->type ) {

  case DEBUGGER_EXPRESSION_TYPE_INTEGER:
    return exp->types.integer;

  case DEBUGGER_EXPRESSION_TYPE_REGISTER:
    return debugger_register_get( exp->types.reg );

  default:
    ui_error( UI_ERROR_ERROR, "unknown expression type %d", exp->type );
    return 0;
  }
}