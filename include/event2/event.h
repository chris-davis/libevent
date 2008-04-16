/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _EVENT2_EVENT_H_
#define _EVENT2_EVENT_H_

/** @file event.h

  Core functions for waiting for and receiving events, and using event bases.

 */

#ifdef __cplusplus
extern "C" {
#endif

#include <event-config.h>
#ifdef _EVENT_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* For int types. */
#include <event2/util.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
typedef unsigned char u_char;
typedef unsigned short u_short;
#endif

struct event_base;
struct event;

/**
  Initialize the event API.

  Use event_base_new() to initialize a new event base, but does not set
  the current_base global.   If using only event_base_new(), each event
  added must have an event base set with event_base_set()

  @see event_base_set(), event_base_free(), event_init()
 */
struct event_base *event_base_new(void);

/**
  Reinitialized the event base after a fork

  Some event mechanisms do not survive across fork.   The event base needs
  to be reinitialized with the event_reinit() function.

  @param base the event base that needs to be re-initialized
  @return 0 if successful, or -1 if some events could not be re-added.
  @see event_base_new(), event_init()
*/
int event_reinit(struct event_base *base);

/**
  Threadsafe event dispatching loop.

  @param eb the event_base structure returned by event_init()
  @see event_init(), event_dispatch()
 */
int event_base_dispatch(struct event_base *);


/**
 Get the kernel event notification mechanism used by libevent.
 
 @param eb the event_base structure returned by event_base_new()
 @return a string identifying the kernel event mechanism (kqueue, epoll, etc.)
 */
const char *event_base_get_method(struct event_base *);
        
        
/**
  Deallocate all memory associated with an event_base, and free the base.

  Note that this function will not close any fds or free any memory passed
  to event_set as the argument to callback.

  @param eb an event_base to be freed
 */
void event_base_free(struct event_base *);

#define _EVENT_LOG_DEBUG 0
#define _EVENT_LOG_MSG   1
#define _EVENT_LOG_WARN  2
#define _EVENT_LOG_ERR   3
typedef void (*event_log_cb)(int severity, const char *msg);
/**
  Redirect libevent's log messages.

  @param cb a function taking two arguments: an integer severity between
     _EVENT_LOG_DEBUG and _EVENT_LOG_ERR, and a string.  If cb is NULL,
	 then the default log is used.
  */
void event_set_log_callback(event_log_cb cb);

/**
  Associate a different event base with an event.

  @param eb the event base
  @param ev the event
 */
int event_base_set(struct event_base *, struct event *);

/**
 event_loop() flags
 */
/*@{*/
#define EVLOOP_ONCE	0x01	/**< Block at most once. */
#define EVLOOP_NONBLOCK	0x02	/**< Do not block. */
/*@}*/

/**
  Handle events (threadsafe version).

  This is a more flexible version of event_base_dispatch().

  @param eb the event_base structure returned by event_init()
  @param flags any combination of EVLOOP_ONCE | EVLOOP_NONBLOCK
  @return 0 if successful, -1 if an error occurred, or 1 if no events were
    registered.
  @see event_loopexit(), event_base_loop()
  */
int event_base_loop(struct event_base *, int);

/**
  Exit the event loop after the specified time (threadsafe variant).

  The next event_base_loop() iteration after the given timer expires will
  complete normally (handling all queued events) then exit without
  blocking for events again.

  Subsequent invocations of event_base_loop() will proceed normally.

  @param eb the event_base structure returned by event_init()
  @param tv the amount of time after which the loop should terminate.
  @return 0 if successful, or -1 if an error occurred
  @see event_loopexit()
 */
int event_base_loopexit(struct event_base *, struct timeval *);

/**
  Abort the active event_base_loop() immediately.

  event_base_loop() will abort the loop after the next event is completed;
  event_base_loopbreak() is typically invoked from this event's callback.
  This behavior is analogous to the "break;" statement.

  Subsequent invocations of event_loop() will proceed normally.

  @param eb the event_base structure returned by event_init()
  @return 0 if successful, or -1 if an error occurred
  @see event_base_loopexit
 */
int event_base_loopbreak(struct event_base *);

/**
  Define a timer event.

  @param ev event struct to be modified
  @param cb callback function
  @param arg argument that will be passed to the callback function
 */
#define evtimer_set(ev, cb, arg)	event_set(ev, -1, 0, cb, arg)

/**
  Add a timer event.

  @param ev the event struct
  @param tv timeval struct
 */
#define evtimer_add(ev, tv)		event_add(ev, tv)

/**
  Define a timer event.

  @param ev event struct to be modified
  @param cb callback function
  @param arg argument that will be passed to the callback function
 */
#define evtimer_set(ev, cb, arg)	event_set(ev, -1, 0, cb, arg)


/**
 * Delete a timer event.
 *
 * @param ev the event struct to be disabled
 */
#define evtimer_del(ev)			event_del(ev)
#define evtimer_pending(ev, tv)		event_pending(ev, EV_TIMEOUT, tv)
#define evtimer_initialized(ev)		((ev)->ev_flags & EVLIST_INIT)

/**
 * Add a timeout event.
 *
 * @param ev the event struct to be disabled
 * @param tv the timeout value, in seconds
 */
#define timeout_add(ev, tv)		event_add(ev, tv)


/**
 * Define a timeout event.
 *
 * @param ev the event struct to be defined
 * @param cb the callback to be invoked when the timeout expires
 * @param arg the argument to be passed to the callback
 */
#define timeout_set(ev, cb, arg)	event_set(ev, -1, 0, cb, arg)


/**
 * Disable a timeout event.
 *
 * @param ev the timeout event to be disabled
 */
#define timeout_del(ev)			event_del(ev)

#define timeout_pending(ev, tv)		event_pending(ev, EV_TIMEOUT, tv)
#define timeout_initialized(ev)		((ev)->ev_flags & EVLIST_INIT)

#define signal_add(ev, tv)		event_add(ev, tv)
#define signal_set(ev, x, cb, arg)	\
	event_set(ev, x, EV_SIGNAL|EV_PERSIST, cb, arg)
#define signal_del(ev)			event_del(ev)
#define signal_pending(ev, tv)		event_pending(ev, EV_SIGNAL, tv)
#define signal_initialized(ev)		((ev)->ev_flags & EVLIST_INIT)


/**
  Prepare an event structure to be added.

  The function event_set() prepares the event structure ev to be used in
  future calls to event_add() and event_del().  The event will be prepared to
  call the function specified by the fn argument with an int argument
  indicating the file descriptor, a short argument indicating the type of
  event, and a void * argument given in the arg argument.  The fd indicates
  the file descriptor that should be monitored for events.  The events can be
  either EV_READ, EV_WRITE, or both.  Indicating that an application can read
  or write from the file descriptor respectively without blocking.

  The function fn will be called with the file descriptor that triggered the
  event and the type of event which will be either EV_TIMEOUT, EV_SIGNAL,
  EV_READ, or EV_WRITE.  The additional flag EV_PERSIST makes an event_add()
  persistent until event_del() has been called.

  @param ev an event struct to be modified
  @param fd the file descriptor to be monitored
  @param event desired events to monitor; can be EV_READ and/or EV_WRITE
  @param fn callback function to be invoked when the event occurs
  @param arg an argument to be passed to the callback function

  @see event_add(), event_del(), event_once()

 */
void event_set(struct event *, evutil_socket_t, short, void (*)(evutil_socket_t, short, void *), void *);

/**
  Schedule a one-time event (threadsafe variant)

  The function event_base_once() is similar to event_set().  However, it
  schedules a callback to be called exactly once and does not require the
  caller to prepare an event structure.

  @param base an event_base returned by event_init()
  @param fd a file descriptor to monitor
  @param events event(s) to monitor; can be any of EV_TIMEOUT | EV_READ |
         EV_WRITE
  @param callback callback function to be invoked when the event occurs
  @param arg an argument to be passed to the callback function
  @param timeout the maximum amount of time to wait for the event, or NULL
         to wait forever
  @return 0 if successful, or -1 if an error occurred
  @see event_once()
 */
int event_base_once(struct event_base *, evutil_socket_t, short, void (*)(evutil_socket_t, short, void *), void *, struct timeval *);

/**
  Add an event to the set of monitored events.

  The function event_add() schedules the execution of the ev event when the
  event specified in event_set() occurs or in at least the time specified in
  the tv.  If tv is NULL, no timeout occurs and the function will only be
  called if a matching event occurs on the file descriptor.  The event in the
  ev argument must be already initialized by event_set() and may not be used
  in calls to event_set() until it has timed out or been removed with
  event_del().  If the event in the ev argument already has a scheduled
  timeout, the old timeout will be replaced by the new one.

  @param ev an event struct initialized via event_set()
  @param timeout the maximum amount of time to wait for the event, or NULL
         to wait forever
  @return 0 if successful, or -1 if an error occurred
  @see event_del(), event_set()
  */
int event_add(struct event *, struct timeval *);

/**
  Remove an event from the set of monitored events.

  The function event_del() will cancel the event in the argument ev.  If the
  event has already executed or has never been added the call will have no
  effect.

  @param ev an event struct to be removed from the working set
  @return 0 if successful, or -1 if an error occurred
  @see event_add()
 */
int event_del(struct event *);


/**
  Make an event active.

  @param ev an event to make active.
  @param res a set of flags to pass to the event's callback.
  @param ncalls
 **/
void event_active(struct event *, int, short);


/**
  Checks if a specific event is pending or scheduled.

  @param ev an event struct previously passed to event_add()
  @param event the requested event type; any of EV_TIMEOUT|EV_READ|
         EV_WRITE|EV_SIGNAL
  @param tv an alternate timeout (FIXME - is this true?)

  @return 1 if the event is pending, or 0 if the event has not occurred

 */
int event_pending(struct event *, short, struct timeval *);


/**
  Test if an event structure has been initialized.

  The event_initialized() macro can be used to check if an event has been
  initialized.

  @param ev an event structure to be tested
  @return 1 if the structure has been initialized, or 0 if it has not been
          initialized
 */
#ifdef WIN32
#define event_initialized(ev)		((ev)->ev_flags & EVLIST_INIT && (ev)->ev_fd != (int)INVALID_HANDLE_VALUE)
#else
#define event_initialized(ev)		((ev)->ev_flags & EVLIST_INIT)
#endif


/**
  Get the libevent version number.

  @return a string containing the version number of libevent
 */
const char *event_get_version(void);


/**
  Set the number of different event priorities (threadsafe variant).

  See the description of event_priority_init() for more information.

  @param eb the event_base structure returned by event_init()
  @param npriorities the maximum number of priorities
  @return 0 if successful, or -1 if an error occurred
  @see event_priority_init(), event_priority_set()
 */
int	event_base_priority_init(struct event_base *, int);


/**
  Assign a priority to an event.

  @param ev an event struct
  @param priority the new priority to be assigned
  @return 0 if successful, or -1 if an error occurred
  @see event_priority_init()
  */
int	event_priority_set(struct event *, int);

/**
 Override the functions that libevent uses for memory management.

 Usually, libevent uses the standard libc functions malloc, realloc, and
 free to allocate memory.  Passing replacements for those functions to
 event_set_mem_functions() overrides this behavior.  To restore the default
 behavior, pass NULLs as the arguments to this function.

 Note that all memory returned from libevent will be allocated by the
 replacement functions rather than by malloc() and realloc().  Thus, if you
 have replaced those functions, it may not be appropriate to free() memory
 that you get from libevent.

 @param malloc_fn A replacement for malloc.
 @param realloc_fn A replacement for realloc
 @param free_fn A replacement for free.
 **/
void event_set_mem_functions(void *(*malloc_fn)(size_t sz),
                             void *(*realloc_fn)(void *ptr, size_t sz),
                             void (*free_fn)(void *ptr));

#ifdef __cplusplus
}
#endif

#endif /* _EVENT2_EVENT_H_ */