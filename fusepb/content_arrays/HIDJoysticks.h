/* HIDJoysticks.h: Object encapsulating SDL joysticks
   Copyright (c) 2005 Fredrick Meunier

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

#import <Cocoa/Cocoa.h>

@interface HIDJoystick : NSObject <NSCoding>
{
  NSString *name;
  int type;
}

+ (NSArray *)allJoysticks;
+ (id)joystickWithName:(NSString *)aTitle andType:(int)aValue;
+ (HIDJoystick *)joystickForName:(NSString *)theName;
+ (HIDJoystick *)joystickForType:(int)theType;
@property (retain,getter=joystickName,setter=setJoystickName:) NSString *name;
@property (getter=joystickType,setter=setJoystickType:) int type;

- (id)copyWithZone:(NSZone *)zone;
- (id)valueForUndefinedKey:(NSString *)key;
@end
