
#ifndef FUSE_DEBUGGER_GDBSERVER_H
#define FUSE_DEBUGGER_GDBSERVER_H

void gdbserver_init();
int gdbserver_start( int port );
int gdbserver_activate();

#endif				/* #ifndef FUSE_DEBUGGER_GDBSERVER_H */
