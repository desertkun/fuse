---
title: The Poke Finder
description: This section describes the Fuse poke finder.
order: 160
---

The 'poke finder' is a tool which is designed to make the task of finding (infinite lives etc) pokes for games a bit easier: it is similar to the 'Lifeguard' utility which was available for use with the Multiface. It works by maintaining a list of locations in which the current number of lives (etc) may be stored, and having the ability to remove from that list any locations which don't contain a specified value.

The poke finder dialog contains an entry box for specifying the value to be searched for, a count of the current number of possible locations and, if there are less than 20 possible locations, a list of the possible locations (in 'page:offset' format). The five buttons act as follows:

BUTTON | ACTION
:--- | :---
*Incremented* | Remove from the list of possible locations all addresses which have not been incremented since the last search.
*Decremented* | Remove from the list of possible locations all addresses which have not been deccremented since the last search.
*Search* | Remove from the list of possible locations all addresses which do not contain the value specified in the 'Search for' field.
*Reset* | Reset the poke finder so that all locations are considered possible.
*OK* | Close the dialog. Note that this does not reset the current state of the poke finder.

<br>
An example of how to use this may make things a bit clearer. We'll use the 128K version of Gryzor. Load the game, define keys to suit and start playing. Immediately pause the game and bring up the poke finder dialog. We note that we currently have 6 lives, so enter '6' into the 'Search for' field and click 'Search'. This reduces the number of possible locations to around 931 (you may get a slightly different number depending on exactly when you paused the game). Play along a bit and then (deliberately) lose a life. Pause the game again. As we now have 5 lives, replace the '6' in the 'Search for' field with a '5' and click 'Search' again. This then reduces the list of possible locations to just one: page 2, offset 0x00BC. This is the only location in memory which stored '6' when we had 6 lives and '5' when we had 5 lives, so its pretty likely that this is where the lives count is stored. Double-clicking on the '2:0x00BC' entry in the dialog will set the appropriate breakpoint (you may wish to open the debugger at this point to confirm this). Play along a bit more. When you next lose a life, emulation is stopped with PC at 0x91CD. Scrolling up a few addresses in the debugger's disassembly pane shows a value was loaded from 0x80BC (our hypothetical lives counter), decremented and then stored again to 0x80BC, which looks very much like the code to reduce the number of lives. We can now use the debugger to replace the decrement with a NOP ('set 0x91C9 0'), and playing the game some more after this reveals that this has worked and we now have infinite lives.
