
#include "config.h"

#include "debugger.h"
#include "gdbserver.h"
#include "packets.h"
#include "arch.h"
#include "gdbserver_utils.h"

#include "debugger_internals.h"
#include "event.h"
#include "fuse.h"
#include "infrastructure/startup_manager.h"
#include "memory.h"
#include "mempool.h"
#include "periph.h"
#include "ui/ui.h"
#include "z80/z80.h"
#include "z80/z80_macros.h"

#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <semaphore.h>

typedef void (*trapped_action_t)(const void* data, void* response);

static int gdbserver_socket;
static int gdbserver_client_socket = -1;
static uint8_t tmpbuf[0x20000];
static volatile char gdbserver_trapped = 0;

static sem_t* trap_mutex;
static sem_t* response_mutex;
static trapped_action_t scheduled_action = NULL;
static const void* scheduled_action_data = NULL;
static void* scheduled_action_response = NULL;
static pthread_mutex_t trap_process_mutex;

static libspectrum_word* registers[] = {
    &AF,
    &BC,
    &DE,
    &HL,
    &IX,
    &IY,
    &SP,
    NULL,
    &AF_,
    &BC_,
    &DE_,
    &HL_
};

static void gdbserver_detrap();
static void gdbserver_execute_on_main_thread(trapped_action_t call, const void* data, void* response);

static void action_get_registers(const void* arg, void* response);
static void action_get_mem(const void* arg, void* response);
static void action_set_mem(const void* arg, void* response);
static void action_get_register(const void* arg, void* response);
static void action_set_register(const void* arg, void* response);
static void action_set_breakpoint(const void* arg, void* response);
static void action_remove_breakpoint(const void* arg, void* response);
static void action_step_instruction(const void* arg, void* response);

struct action_mem_args_t {
    size_t maddr, mlen;
    uint8_t* payload;
};

struct action_register_args_t {
    int reg;
    libspectrum_word value;
};

struct action_breakpoint_args_t {
    size_t maddr, mlen;
};

static void process_xfer(const char *name, char *args)
{
  const char *mode = args;
  args = strchr(args, ':');
  *args++ = '\0';
  
  if (!strcmp(name, "features") && !strcmp(mode, "read"))
      write_packet(FEATURE_STR);
  /*
  if (!strcmp(name, "auxv") && !strcmp(mode, "read"))
      read_auxv();
  */
  if (!strcmp(name, "exec-file") && !strcmp(mode, "read"))
  {
      write_packet("/fuse/emulated");
  }
}

static void process_query(char *payload)
{
    const char *name;
    char *args;

    args = strchr(payload, ':');
    if (args)
        *args++ = '\0';
    name = payload;
    if (!strcmp(name, "C"))
    {
        snprintf(tmpbuf, sizeof(tmpbuf), "QCp%02x.%02x", 1, 1);
        write_packet(tmpbuf);
    }
    if (!strcmp(name, "Attached"))
    {
        write_packet("1");
    }
    if (!strcmp(name, "Offsets"))
        write_packet("");
    if (!strcmp(name, "Supported"))
        write_packet("PacketSize=4000;qXfer:features:read+;qXfer:auxv:read+");
    if (!strcmp(name, "Symbol"))
        write_packet("OK");
    if (name == strstr(name, "ThreadExtraInfo"))
    {
        args = payload;
        args = 1 + strchr(args, ',');
        write_packet("41414141");
    }
    if (!strcmp(name, "TStatus"))
        write_packet("");
    if (!strcmp(name, "Xfer"))
    {
        name = args;
        args = strchr(args, ':');
        *args++ = '\0';
        return process_xfer(name, args);
    }
    if (!strcmp(name, "fThreadInfo"))
    {
        write_packet("mp01.01");
    }
    if (!strcmp(name, "sThreadInfo"))
        write_packet("l");
}

static void process_vpacket(char *payload)
{
    const char *name;
    char *args;
    args = strchr(payload, ';');
    if (args)
        *args++ = '\0';
    name = payload;

    if (!strcmp("Cont", name))
    {
        if (args[0] == 'c')
        {
            if (gdbserver_trapped)
            {
                gdbserver_detrap();
                write_packet("OK");
            }
            else
            {
                write_packet("E01");
            }
        }
        if (args[0] == 's')
        {
            if (gdbserver_trapped)
            {
                gdbserver_execute_on_main_thread(action_step_instruction, NULL, NULL);
                gdbserver_detrap();
            }
        }
    }
    if (!strcmp("Cont?", name))
      write_packet("vCont;c;C;s;S;");
    if (!strcmp("Kill", name))
    {
      write_packet("OK");
    }
    if (!strcmp("MustReplyEmpty", name))
      write_packet("");
}

static int set_register_value(int reg, libspectrum_word value)
{
    switch (reg)
    {
        case 7:
        {
            break;
        }
        default:
        {
            if (reg >= (sizeof(registers) / (sizeof(libspectrum_word*))))
            {
                return 1;
            }
            *registers[reg] = value;
            return 0;
        }
    }
  
    return 0;
}

static int get_register_value(int reg, libspectrum_word* result)
{
    switch (reg)
    {
        case 7:
        {
            *result = IR;
            return 0;
            break;
        }
        default:
        {
            if (reg >= (sizeof(registers) / (sizeof(libspectrum_word*))))
            {
                return 1;
            }
            *result = *registers[reg];
            return 0;
        }
    }
  
    return 0;
}

static void process_packet()
{
    uint8_t *inbuf = inbuf_get();
    int inbuf_size = inbuf_end();
    printf("r: %.*s\n", inbuf_size, inbuf);
  
    if (inbuf_size == 1 && *inbuf == 0x03)
    {
        inbuf_reset();
        debugger_mode = DEBUGGER_MODE_HALTED;
        return;
    }
  
    uint8_t *packetend_ptr = (uint8_t *)memchr(inbuf, '#', inbuf_size);
    int packetend = packetend_ptr - inbuf;
    assert('$' == inbuf[0]);
    char request = inbuf[1];
    char *payload = (char *)&inbuf[2];
    inbuf[packetend] = '\0';

    uint8_t checksum = 0;
    uint8_t checksum_str[3];
    for (int i = 1; i < packetend; i++)
        checksum += inbuf[i];
    assert(checksum == (hex(inbuf[packetend + 1]) << 4 | hex(inbuf[packetend + 2])));

    switch (request)
    {
        case 'D':
        {
            if (gdbserver_trapped)
            {
                gdbserver_detrap();
            }
            break;
        }
        case 'g':
        {
            gdbserver_execute_on_main_thread(action_get_registers, NULL, tmpbuf);
            write_packet(tmpbuf);
            break;
        }
        case 'H':
        {
            write_packet("OK");
            break;
        }
        case 'm':
        {
            struct action_mem_args_t mem;
            assert(sscanf(payload, "%zx,%zx", &mem.maddr, &mem.mlen) == 2);
            if (mem.mlen * SZ * 2 > 0x20000)
            {
              puts("Buffer overflow!");
              exit(-1);
            }
          
            gdbserver_execute_on_main_thread(action_get_mem, &mem, tmpbuf);
            write_packet(tmpbuf);
            break;
        }
        case 'M':
        {
            struct action_mem_args_t mem;
            assert(sscanf(payload, "%zx,%zx", &mem.maddr, &mem.mlen) == 2);
          
            mem.payload = payload;
            gdbserver_execute_on_main_thread(action_set_mem, &mem, tmpbuf);
            write_packet(tmpbuf);
            break;
        }
        case 'p':
        {
            struct action_register_args_t r;
            r.reg = strtol(payload, NULL, 16);
            gdbserver_execute_on_main_thread(action_get_register, &r, tmpbuf);
            write_packet(tmpbuf);
            break;
        }
        case 'P':
        {
            struct action_register_args_t r;
            r.reg = strtol(payload, NULL, 16);
            assert('=' == *payload++);
          
            hex2mem(payload, (void *)&r.value, SZ * 2);
          
            gdbserver_execute_on_main_thread(action_set_register, &r, tmpbuf);
            write_packet(tmpbuf);
          
            break;
        }
        case 'q':
        {
            process_query(payload);
            break;
        }
        case 'v':
        {
            process_vpacket(payload);
            break;
        }
        case 'X':
        {
            size_t maddr, mlen;
            int offset, new_len;
            assert(sscanf(payload, "%zx,%zx:%n", &maddr, &mlen, &offset) == 2);
            payload += offset;
            new_len = unescape(payload, (char *)packetend_ptr - payload);
            assert(new_len == mlen);
          
            struct action_mem_args_t mem;
            mem.payload = payload;
            mem.maddr = maddr;
            mem.mlen = mlen;
          
            gdbserver_execute_on_main_thread(action_set_mem, &mem, tmpbuf);
            write_packet(tmpbuf);
            break;
        }
        case 'Z':
        {
            size_t type, addr, length;
            assert(sscanf(payload, "%zx,%zx,%zx", &type, &addr, &length) == 3);
          
            struct action_breakpoint_args_t b;
            b.maddr = addr;
          
            gdbserver_execute_on_main_thread(action_set_breakpoint, &b, tmpbuf);
            write_packet(tmpbuf);
        
            break;
        }
        case 'z':
        {
            size_t type, addr, length;
            assert(sscanf(payload, "%zx,%zx,%zx", &type, &addr, &length) == 3);
          
            struct action_breakpoint_args_t b;
            b.maddr = addr;
          
            gdbserver_execute_on_main_thread(action_remove_breakpoint, &b, tmpbuf);
            write_packet(tmpbuf);
        
            break;
        }
        case '?':
        {
            if (gdbserver_trapped)
            {
                write_packet("S05");
            }
            else
            {
                write_packet("OK");
            }
            break;
        }
        default:
        {
            write_packet("");
        }
    }

    inbuf_erase_head(packetend + 3);
}


static int process_network(int socket)
{
    int ret;
    if ((ret = read_packet(socket)))
    {
        return ret;
    }
  
    acknowledge_packet(socket);
    process_packet();
    write_flush(socket);
    return 0;
}

static void* network_thread(void* arg)
{
    while (1)
    {
        socklen_t socklen;
        struct sockaddr_in connected_addr;
        gdbserver_client_socket = accept(gdbserver_socket, (struct sockaddr*)&connected_addr, &socklen);
        if (gdbserver_client_socket < 0)
        {
            printf("Accept error: %d\n", gdbserver_client_socket);
            continue;
        }
      
        int optval = 1;
        setsockopt (gdbserver_client_socket, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(optval));
        int interval = 1;
        setsockopt(gdbserver_client_socket, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int));
        int maxpkt = 10;
        setsockopt(gdbserver_client_socket, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int));
      
      
        printf("Accepted new socket: %d\n", gdbserver_client_socket);
        int ret;
        while ((ret = process_network(gdbserver_client_socket)) == 0) ;
        printf("Socket closed: %d\n", gdbserver_client_socket);
        close(gdbserver_client_socket);
        gdbserver_client_socket = -1;
    }
}

void gdbserver_init()
{
    pthread_mutex_init(&trap_process_mutex, NULL);
  
    sem_unlink("gdbserver_trap");
    trap_mutex = sem_open("gdbserver_trap", O_CREAT|O_EXCL, 0600, 0);

    sem_unlink("gdbserver_response");
    response_mutex = sem_open("gdbserver_response", O_CREAT|O_EXCL, 0600, 0);
}

int gdbserver_start( int port )
{
    gdbserver_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (gdbserver_socket == -1)
    {
        return 1;
    }
  
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
  
    if ((bind(gdbserver_socket, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0)
    {
        return 2;
    }
  
    if ((listen(gdbserver_socket, 5)) != 0)
    {
        return 3;
    }
  
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, network_thread, NULL) != 0)
    {
        return 4;
    }
  
    //pthread_join(thread_id, NULL);
  
    return 0;
}

static void gdbserver_detrap()
{
    gdbserver_trapped = 0;
    sem_post(trap_mutex);
}

// schedule a simple job (call) on the main thread, while it's trapped
// data and response are supposed to be located on the stack of the caller (network) thread,
// as it's going to be stopped until the response is there
static void gdbserver_execute_on_main_thread(trapped_action_t call, const void* data, void* response)
{
    assert(gdbserver_trapped == 1);

    // prepare the action arguments
    pthread_mutex_lock(&trap_process_mutex);
    scheduled_action = call;
    scheduled_action_data = data;
    scheduled_action_response = response;
    pthread_mutex_unlock(&trap_process_mutex);
  
    // notify the function below
    sem_post(trap_mutex);
  
    // wait for the response
    sem_wait(response_mutex);
}

static void action_get_registers(const void* arg, void* response)
{
    int i;
    uint8_t* resp_buff = (uint8_t*)response;
  
    uint8_t regbuf[20];
    resp_buff[0] = '\0';
    for (i = 0; i < sizeof(registers) / (sizeof(libspectrum_word*)); i++)
    {
        libspectrum_word reg;
        get_register_value(i, &reg);
        mem2hex((void*)&reg, regbuf, SZ);
        regbuf[SZ * 2] = '\0';
        strcat(resp_buff, regbuf);
    }
}

static void action_get_mem(const void* arg, void* response)
{
    int i;
    struct action_mem_args_t* mem = (struct action_mem_args_t*)arg;
    uint8_t* resp_buff = (uint8_t*)response;
  
    libspectrum_word address = mem->maddr;
    for (i = 0; i < mem->mlen; i++, address++)
    {
        libspectrum_byte data = readbyte(address);
        mem2hex((void *)&data, resp_buff + i * 2, 1);
    }

    resp_buff[mem->mlen * 2] = '\0';
}

static void action_set_mem(const void* arg, void* response)
{
    int i;
    struct action_mem_args_t* mem = (struct action_mem_args_t*)arg;
    uint8_t* resp_buff = (uint8_t*)response;
  
    libspectrum_byte data;
    libspectrum_word address = mem->maddr;
    for (i = 0; i < mem->mlen; i++, address++)
    {
        hex2mem(mem->payload + i * 2, (void *)&data, 1);
        writebyte(address, data);
    }
  
    strcpy(resp_buff, "OK");
}

static void action_get_register(const void* arg, void* response)
{
    struct action_register_args_t* r = (struct action_register_args_t*)arg;
    uint8_t* resp_buff = (uint8_t*)response;
  
    if (r->reg == PC_REGISTER)
    {
        mem2hex((void*)&PC, resp_buff, SZ);
        resp_buff[SZ * 2] = '\0';
        return;
    }

    libspectrum_word reg;
    if (get_register_value(r->reg, &reg))
    {
        strcpy(resp_buff, "E01");
        return;
    }

    mem2hex((void *)&reg, resp_buff, SZ);
    resp_buff[SZ * 2] = '\0';
}

static void action_set_register(const void* arg, void* response)
{
    struct action_register_args_t* r = (struct action_register_args_t*)arg;
    uint8_t* resp_buff = (uint8_t*)response;
  
    if (r->reg == PC_REGISTER)
    {
        PC = r->value;
    }
    else
    {
        if (set_register_value(r->reg, r->value))
        {
            strcpy(resp_buff, "E01");
            return;
        }
    }

    strcpy(resp_buff, "OK");
}

static void action_set_breakpoint(const void* arg, void* response)
{
    struct action_breakpoint_args_t* b = (struct action_breakpoint_args_t*)arg;
    uint8_t* resp_buff = (uint8_t*)response;
  
    if (debugger_breakpoint_add_address(
        DEBUGGER_BREAKPOINT_TYPE_EXECUTE, memory_source_any, 0, b->maddr, 0,
        DEBUGGER_BREAKPOINT_LIFE_PERMANENT, NULL))
    {
        strcpy(resp_buff, "E01");
    }
    else
    {
        strcpy(resp_buff, "OK");
    }
}

static void action_remove_breakpoint(const void* arg, void* response)
{
    struct action_breakpoint_args_t* b = (struct action_breakpoint_args_t*)arg;
    uint8_t* resp_buff = (uint8_t*)response;
  
    libspectrum_word address = b->maddr;
    GSList* ptr;
    debugger_breakpoint* found = NULL;
    for(ptr = debugger_breakpoints; ptr; ptr = ptr->next)
    {
        debugger_breakpoint* p = (debugger_breakpoint*)ptr->data;
        if (p->type != DEBUGGER_BREAKPOINT_TYPE_EXECUTE)
            continue;
        if (p->value.address.source != memory_source_any)
            continue;
        if (p->value.address.offset != address)
            continue;
        found = p;
        break;
    }

    if (found)
    {
        debugger_breakpoint_remove(found->id);
        strcpy(resp_buff, "OK");
    }
    else
    {
        strcpy(resp_buff, "E01");
    }
}

static void action_step_instruction(const void* arg, void* response)
{
    size_t length;

    /* Find out how long the current instruction is */
    debugger_disassemble( NULL, 0, &length, PC );

    /* And add a breakpoint after that */
    debugger_breakpoint_add_address(
        DEBUGGER_BREAKPOINT_TYPE_EXECUTE, memory_source_any, 0, PC + length, 0,
        DEBUGGER_BREAKPOINT_LIFE_ONESHOT, NULL
    );
}

int gdbserver_activate()
{
    if (gdbserver_client_socket == -1)
    {
        printf("gdbserver: trap skipped since noone is connected.\n");
        return 0;
    }

    printf("Execution stopped: trapped.\n");
    gdbserver_trapped = 1;

    // notify the gdb client that we have trapped
    char tbuf[64];
    sprintf(tbuf, "T%02xthread:p%02x.%02x;", 5, 1, 1);
    write_packet(tbuf);
    write_flush(gdbserver_client_socket);
  
    // a simple loop that waits for someone to unlock, or postone a simple
    // action (only one at a time)
    do
    {
        sem_wait(trap_mutex);
      
        if (!gdbserver_trapped)
        {
            break;
        }
      
        pthread_mutex_lock(&trap_process_mutex);
        if (scheduled_action != NULL)
        {
            scheduled_action(scheduled_action_data, scheduled_action_response);
          
            // notify the waiter that we're done
            sem_post(response_mutex);
        }
        pthread_mutex_unlock(&trap_process_mutex);
      
    } while (1);
  
    debugger_mode = DEBUGGER_MODE_ACTIVE;
    printf("Execution resumed.\n");
    return 0;
}
