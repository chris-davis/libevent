/*
 * Copyright 2010 Christopher Davis <chrisd@torproject.org>
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

/*
 * This backend is based upon a design by Stephen Liu, though it
 * has been rewritten to support Libevent 2.0.
 */

/*

IOCP backend

The Windows select backend has limitations for performance and
scalability. It'd be nice to have a true O(1) method for polling
sockets on Windows like epoll or kqueue, so the kernel is not
tasked with scanning potentially large vectors of sockets on each
dispatch. While Windows doesn't have a neat interface like epoll or
kqueue, we can get by using Windows' overlapped I/O (and in certain
cases event select) to reduce the overhead of finding an active
socket among many monitored sockets. This design originated from
Stephen Liu's backend for Libevent 1.4.x. We've adapted his aproach
for Libevent 2 to remove the EV_CONNECT flag and avoid limiting the
number of sockets monitored with WSAEventSelect/WaitForMultipleObjects.

The backend uses two different means of polling sockets: poll threads
and overlapped read and write. UDP sockets, listeners and unconnected
TCP sockets are added to poll threads, which use WSAEventSelect and
WaitForMultipleObjects for polling. Connected TCP sockets are polled
using overlapped read/write with zero sizes (no data is read or
written, we only want to know when there's active I/O).

A Windows' I/O completion port is used to queue completion packets
resulting from overlapped I/O operations, as well as the event
notifications discovered in poll threads. The backend's dispatch slot
collects completion packets from the IOCP and dispatches them.

*/

#include "event-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <windows.h>
#include <mswsock.h>
#include <winsock.h>
#include <process.h>
#include <sys/queue.h>

#include "event-internal.h"
#include "evsignal-internal.h"
#include "log-internal.h"
#include "evmap-internal.h"
#include "event2/thread.h"
#include "evthread-internal.h"

#define IOCP_KEY_IO 1
#define IOCP_KEY_EVENT 2

struct iocp_loop_ctx;
struct iocp_event;
struct poll_thread;

/** Wrap an OVERLAPPED so we can safely use EVUTIL_UPCAST to find
    the associated iocp event and from there the event type
    (read or write).
*/
struct iocp_overlapped {
	OVERLAPPED ol;
	struct iocp_event *ev;
};

/** The type of the socket. */ 
enum iocp_event_type {
	IOCP_SOCK_UDP,
	IOCP_SOCK_LISTENER,
	IOCP_SOCK_UNCONNECTED,
	IOCP_SOCK_OVERLAPPED,
};

/** Flags for an IOCP event. */
enum iocp_event_flags {
	IOCP_QUEUED = 1<<0,
	IOCP_POLL_READ = 1<<1,
	IOCP_POLL_WRITE = 1<<2,
	IOCP_LAUNCHED_READ = 1<<3,
	IOCP_LAUNCHED_WRITE = 1<<4,
	IOCP_CANCEL = 1<<5,
};

/** The event tracked by the IOCP backend.  */
struct iocp_event {
	/** Links for the overlapped queue. */
	TAILQ_ENTRY(iocp_event) next;

	/** The type of the socket. */
	ev_uint8_t type;

	/** Flags. */
	ev_uint8_t flags;

	/** Socket descriptor. */
	evutil_socket_t sock;

	/** Handle of the event object for use with WSAEventSelect. */
	HANDLE poll_event;

	/** Pointer to the poll thread this iocp event belongs to.
	    We store this in the event object so we don't have to
	    search through the thread pool to find it when we want
	    to remove the event from the poll thread */
	struct poll_thread *poll_thr;

	/** Overlapped object associated with read events. */
	struct iocp_overlapped ord;

	/** Overlapped object associated with write events. */
	struct iocp_overlapped owr;

	/** Reference count. */
	int refcnt;
};

/** A thread that polls sockets that can't be polled through overlapped
    operations. This includes listener sockets, unconnected TCP sockets
    and UDP sockets. The events to poll for are set with 
    iocp_event_update_event_selection(), and the associated event objects
    are monitored in the poll thread. Event notifications are queued in
    the IOCP. A single thread can only handle MAXIMUM_WAIT_OBJECTS - 1
    (one object is saved for shutdown notification) worth of sockets at
    a time, so we use multiple poll threads to monitor greater numbers.
*/
struct poll_thread {
	/** Thread pool links. */
	TAILQ_ENTRY(poll_thread) next;

	/** Handle of the thread. */
	HANDLE handle;

	/** The IOCP backend context. */
	struct iocp_loop_ctx *ctx;

	/** The number of free slots in this thread. */
	size_t nfree;

	/** Windows event objects to wait on. */
	HANDLE waitlist[MAXIMUM_WAIT_OBJECTS];

	/** IOCP backend events being monitored. */
	struct iocp_event *evlist[MAXIMUM_WAIT_OBJECTS];
};

/** The context for the IOCP backend */
struct iocp_loop_ctx {
	/** Handle of the IOCP. */
	HANDLE iocp;
	
	/** Poll thread pool. */
	TAILQ_HEAD(poll_thread_list, poll_thread) notify_pool;

	/** Queue of events that have pending overlapped operations */
	TAILQ_HEAD(iocp_event_list, iocp_event) overlapped_queue;

	/** Number of events activated in a call to iocp_loop_dispatch() */
	size_t nactivated;

	/** The event base; poll threads need access to the base lock. */
	struct event_base *base;
};

/** Find the type of a socket.

    @param sock The socket
*/
static int
get_sock_type(evutil_socket_t sock)
{
	int intval;
	DWORD dwval;
	int len;
	int rv;
	
	/* Is this a UDP socket? */
	len = sizeof(int);
	intval = 0;
	rv = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&intval, &len);
	if (rv == SOCKET_ERROR)
		return -1;
	if (intval == SOCK_DGRAM)
		return IOCP_SOCK_UDP;

	/* If this socket isn't UDP or TCP, there's not much we can do. */
	if (intval != SOCK_STREAM)
		return -1;

	/* Is this socket a listener? */
	len = sizeof(int);
	intval = 0;
	rv = getsockopt(sock, SOL_SOCKET, SO_ACCEPTCONN, (char*)&intval, &len);
	if (rv == SOCKET_ERROR)
		return -1;
	if (intval)
		return IOCP_SOCK_LISTENER;

	/* Is this socket not connected yet? */
	len = sizeof(DWORD);
	dwval = 0;
	rv = getsockopt(sock, SOL_SOCKET, SO_CONNECT_TIME, (char*)&dwval, &len);
	if (rv == SOCKET_ERROR || dwval == (DWORD)-1)
		return IOCP_SOCK_UNCONNECTED;

	return IOCP_SOCK_OVERLAPPED;
}

/** Allocate a new IOCP event structure.

    @param ctx The IOCP backend context.
    @param sock The socket to monitor.
*/
static struct iocp_event *
iocp_event_new(struct iocp_loop_ctx *ctx, evutil_socket_t sock)
{
	int type;
	struct iocp_event *iev;

	type = get_sock_type(sock);
	if (type < 0)
		return NULL;

	if (!CreateIoCompletionPort((HANDLE)sock, ctx->iocp, IOCP_KEY_IO, 1)) {
		int err = GetLastError();
		/* If we get invalid parameter error, assume that the socket was
		 * previously associated with the iocp */
		if (err != ERROR_INVALID_PARAMETER) {
			event_warnx("CreateIoCompletionPort(): error %d", err);
			return NULL;
		}
	}

	iev = mm_calloc(1, sizeof(*iev));
	if (!iev)
		return NULL;

	iev->sock = sock;
	iev->type = type;
	iev->refcnt = 1;
	iev->ord.ev = iev;
	iev->owr.ev = iev;

	return iev;
}

/** Add a reference to an IOCP event object.

    @param iev The IOCP event object.
*/
static void
iocp_event_incref(struct iocp_event *iev)
{
	iev->refcnt++;
}

/** Remove a reference to an IOCP event object.

    @param iev The IOCP event object.
*/
static void
iocp_event_decref(struct iocp_event *iev)
{
	if (--iev->refcnt <= 0) {
		EVUTIL_ASSERT(iev->poll_thr == NULL);
		iev->ord.ev = NULL;
		iev->owr.ev = NULL;
		mm_free(iev);
	}
}

/** Destroy a poll thread.

    The thread should be stopped first!

    @param poll_thr The poll thread object.
*/
static void
poll_thread_destroy(struct poll_thread *poll_thr)
{
	size_t i;

	EVUTIL_ASSERT(poll_thr->handle == NULL);
	
	for (i = 0; i < MAXIMUM_WAIT_OBJECTS; ++i) {
		CloseHandle(poll_thr->waitlist[i]);
	}

	mm_free(poll_thr);
}

/** Allocate a new poll thread.

    @param ctx The IOCP backend context.
*/
static struct poll_thread *
poll_thread_new(struct iocp_loop_ctx *ctx)
{
	size_t i;
	struct poll_thread *ret;

	ret = mm_calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	/* We save one event object so we can notify the thread
	 * to quit. */
	ret->nfree = MAXIMUM_WAIT_OBJECTS - 1;
	ret->ctx = ctx;

	for (i = 0; i < MAXIMUM_WAIT_OBJECTS; ++i) {
		HANDLE h = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (h == NULL) {
			poll_thread_destroy(ret);
			return NULL;
		}

		ret->waitlist[i] = h;
	}	

	return ret;
}

/** Post an event notification to the IOCP.

    This is a helper for the thread loop. The IOCP context
    should be locked.

    @param poll_thr The poll thread.
    @param i The index of the event.
*/
static void
poll_thread_post(struct poll_thread *poll_thr, DWORD i)
{
	WSANETWORKEVENTS what;
	OVERLAPPED *ol;
	struct iocp_event *iev;

	iev = poll_thr->evlist[i];

	if (!iev)
		return;

	// XXX handle error
	WSAEnumNetworkEvents(iev->sock, NULL, &what);

	if (what.lNetworkEvents & (FD_CONNECT | FD_WRITE))
		ol = &iev->owr.ol;
	else
		ol = &iev->ord.ol;

	iocp_event_incref(iev);

	// XXX handle error
	PostQueuedCompletionStatus(poll_thr->ctx->iocp, 0, IOCP_KEY_EVENT, ol);
}

/** The main poll thread loop.

    @param _poll_thr The poll thread.
*/
static unsigned __stdcall
poll_thread_loop(void *_poll_thr)
{
	DWORD rv;
	struct poll_thread *poll_thr = _poll_thr;
	struct event_base *base = poll_thr->ctx->base;

	while (1) {
		rv = WaitForMultipleObjects(
				MAXIMUM_WAIT_OBJECTS,
				poll_thr->waitlist,
				FALSE,
				-1);

		if (rv == WAIT_FAILED) {
			// XXX
			return 0;
		}

		rv -= WAIT_OBJECT_0;
		EVUTIL_ASSERT(rv >= 0 && rv < MAXIMUM_WAIT_OBJECTS);

		/* We have been asked to quit. */
		if (rv == 0)
			return 0;

		EVBASE_ACQUIRE_LOCK(base, th_base_lock);
		poll_thread_post(poll_thr, rv);
		EVBASE_RELEASE_LOCK(base, th_base_lock);
	}

	return 0;
}

/** Start a poll thread.

    The thread should not be already started!   
 
    @param poll_thr The poll thread.
*/
static int
poll_thread_start(struct poll_thread *poll_thr)
{
	HANDLE th;

	EVUTIL_ASSERT(poll_thr->handle == NULL);

	th = (HANDLE)_beginthreadex(NULL, 0,
			poll_thread_loop, poll_thr, 0, NULL);
	if (th == 0)
		return -1;

	poll_thr->handle = th;

	return 0;
}

/** Stop a poll thread.

    The thread should already be started!   
 
    @param poll_thr The poll thread.
*/
static void
poll_thread_stop(struct poll_thread *poll_thr)
{
	EVUTIL_ASSERT(poll_thr->handle != NULL);

	SetEvent(poll_thr->waitlist[0]);
	WaitForSingleObject(poll_thr->handle, INFINITE);
	CloseHandle(poll_thr->handle);
	
	poll_thr->handle = NULL;
}

/** Add an event to the poll thread.

    @param poll_thr The poll thread.
    @param iev The IOCP event.
    @return 1 if succesfully added, 0 if already full.
*/
static int
poll_thread_add_event(struct poll_thread *poll_thr, struct iocp_event *iev)
{
	size_t i;

	EVUTIL_ASSERT(iev->poll_thr == NULL);

	if (!poll_thr->nfree)
		return 0;

	for (i = 1; i < MAXIMUM_WAIT_OBJECTS; ++i) {
		if (!poll_thr->evlist[i]) {
			iocp_event_incref(iev);
			poll_thr->evlist[i] = iev;
			iev->poll_event = poll_thr->waitlist[i];
			iev->poll_thr = poll_thr;
			poll_thr->nfree--;
			return 1;
		}
	}

	return 0;
}

/** Remove an event to the poll thread.

    @param poll_thr The poll thread.
    @param iev The IOCP event.
    @return 1 if succesfully removed, 0 not found.
*/
static int
poll_thread_del_event(struct poll_thread *poll_thr, struct iocp_event *iev)
{
	size_t i;

	EVUTIL_ASSERT(iev->poll_thr != NULL);

	for (i = 1; i < MAXIMUM_WAIT_OBJECTS; ++i) {
		if (poll_thr->evlist[i] == iev) {
			poll_thr->evlist[i] = NULL;
			iev->poll_thr = NULL;
			iev->poll_event = NULL;
			WSAEventSelect(iev->sock, NULL, 0);
			iocp_event_decref(iev);
			poll_thr->nfree++;
			return 1;
		}
	}

	return 0;
}

/** Set the events a poll thread should monitor.
 
    This translates the socket type and flags into flags
    for WSAEventSelect(). Call this each time the user changes
    the events they want to poll for.

    @param iev The IOCP event.
    @return 0 on success, -1 on failure.
*/
static int
iocp_event_update_event_selection(struct iocp_event *iev)
{
	long nev = 0;

	if (!iev->poll_event || !iev->poll_thr)
		return 0;

	switch (iev->type) {
	case IOCP_SOCK_UDP:
		if (iev->flags & IOCP_POLL_READ)
			nev |= FD_READ;
		if (iev->flags & IOCP_POLL_WRITE)
			nev |= FD_WRITE;
		break;
	case IOCP_SOCK_LISTENER:
		if (iev->flags & IOCP_POLL_READ)
			nev |= FD_ACCEPT;
		break;
	case IOCP_SOCK_UNCONNECTED:
		nev |= FD_CONNECT;
		break;
	case IOCP_SOCK_OVERLAPPED:
	default:
		abort();
	}

	/* XXX It seems we can use WSAEventSelect() when a poll thread
	   is waiting on the event object. */
	if (WSAEventSelect(iev->sock, iev->poll_event, nev) == SOCKET_ERROR)
		return -1;

	return 0;
}

/** Add an event to the poll thread pool.

    If all threads are full, add a new thread automatically.

    @param ctx The IOCP backend context.
    @param iev The IOCP event.
    @return 0 on success, -1 on failure.
*/
static int
poll_thread_pool_add_event(struct iocp_loop_ctx *ctx, struct iocp_event *iev)
{
	struct poll_thread *new_worker, *it;

	TAILQ_FOREACH(it, &ctx->notify_pool, next) {
		if (poll_thread_add_event(it, iev))
			return 0;
	}

	/* All workers are full, so add a new worker. */
	new_worker = poll_thread_new(ctx);
	if (!new_worker)
		return -1;
	if (poll_thread_start(new_worker) < 0 ||
	    !poll_thread_add_event(new_worker, iev)) {
		poll_thread_destroy(new_worker);
		return -1;
	}

	/* Add new threads to the front of the list so we can
	   fill them up without having to iterate to the back */
	TAILQ_INSERT_HEAD(&ctx->notify_pool, new_worker, next);

	return 0;
}

/** Remove an event from the poll event pool.
    
    @param ctx The IOCP backend context.
    @param iev The IOCP event.
    @return 0 on success, -1 on failure.
*/
static int
poll_thread_pool_del_event(struct iocp_loop_ctx *ctx, struct iocp_event *iev)
{
	/* XXX when is a good time to clean up unused worker threads? */

	poll_thread_del_event(iev->poll_thr, iev);

	return 0;
}

/** Stop and destroy all threads in the poll thread pool.

    @param ctx The IOCP backend context.
*/
static void
poll_thread_pool_destroy(struct iocp_loop_ctx *ctx)
{
	struct poll_thread *it;

	while ((it = TAILQ_FIRST(&ctx->notify_pool)) != NULL) {
		TAILQ_REMOVE(&ctx->notify_pool, it, next);
		poll_thread_stop(it);
		poll_thread_destroy(it);
	}
}

/** Queue launching of overlapped operations to poll for events.

    This works on connected TCP sockets only.

    @param ctx The IOCP backend context.
    @param iev The IOCP event to poll.
*/
static void
overlapped_queue_push(struct iocp_loop_ctx *ctx, struct iocp_event *iev)
{
	EVUTIL_ASSERT(iev->type == IOCP_SOCK_OVERLAPPED);

	if (iev->flags & IOCP_QUEUED)
		return;

	iocp_event_incref(iev);
	iev->flags |= IOCP_QUEUED;
	TAILQ_INSERT_TAIL(&ctx->overlapped_queue, iev, next);
}

/** Cancel pending overlapped operations for an event.

    If iev is not pending, remove from queue, otherwise set cancel flag.

    @param ctx The IOCP backend context.
    @param iev The IOCP event. 
*/
static void
overlapped_queue_cancel(struct iocp_loop_ctx *ctx, struct iocp_event *iev)
{
	EVUTIL_ASSERT(iev->type == IOCP_SOCK_OVERLAPPED);

	if (iev->flags & (IOCP_LAUNCHED_READ|IOCP_LAUNCHED_WRITE)) {
		iev->flags |= IOCP_CANCEL;
		if (!(iev->flags & IOCP_QUEUED))
			overlapped_queue_push(ctx, iev);
	} else if (iev->flags & IOCP_QUEUED) {
		TAILQ_REMOVE(&ctx->overlapped_queue, iev, next);
		iev->flags &= ~IOCP_QUEUED;
		iocp_event_decref(iev);
	}
}

/** Launch queued overlapped operations.

    @param ctx The IOCP backend context.
    @return 0 on success, -1 on failure.
*/
static int
overlapped_queue_run_all(struct iocp_loop_ctx *ctx)
{
	int rv;
	struct iocp_event *iev;
	DWORD bytes;

	/* XXX do we need to relaunch failed overlapped operations ? */

	while ((iev = TAILQ_FIRST(&ctx->overlapped_queue)) != NULL) {
		TAILQ_REMOVE(&ctx->overlapped_queue, iev, next);
		iev->flags &= ~IOCP_QUEUED;

		if (iev->flags & IOCP_CANCEL) {
			iocp_event_incref(iev);
			CancelIo((HANDLE)iev->sock);
		} else {
			if ((iev->flags & IOCP_POLL_READ) &&
			    !(iev->flags & IOCP_LAUNCHED_READ)) {
				bytes = 0;
				iev->flags |= IOCP_LAUNCHED_READ;
				iocp_event_incref(iev);
				rv = ReadFile((HANDLE)iev->sock, NULL, 0,
					      &bytes, &iev->ord.ol);
				if (!rv) {
					rv = GetLastError();
					if (rv != ERROR_IO_PENDING)
						event_warnx("ReadFile(): error %d", rv);
				}

			}
			if ((iev->flags & IOCP_POLL_WRITE) &&
			    !(iev->flags & IOCP_LAUNCHED_WRITE)) {
				bytes = 0;
				iev->flags |= IOCP_LAUNCHED_WRITE;
				iocp_event_incref(iev);
				rv = WriteFile((HANDLE)iev->sock, NULL, 0,
					       &bytes, &iev->owr.ol);
				if (!rv) {
					rv = GetLastError();
					if (rv != ERROR_IO_PENDING)
						event_warnx("WriteFile(): error %d", rv);
				}
			}
		}

		/* Remove queue reference. */
		iocp_event_decref(iev);
	}	

	return 0;
}

/** Attempt to fetch a single event from the IOCP.

    The base lock or IOCP context lock needn't be held.	A reference
    to the event is still held. Use iocp_active() to activate the
    event and remove the reference.

    If an overlapped operation was cancelled, what is set to 0.

    @param ctx The IOCP backend context.
    @param ms The maximum amount of time to wait for an event.
    @param iev The fetched event.
    @param what The event type, EV_READ, EV_WRITE or 0.
    @return -1 error, 0 timeout, 1 dispatched or aborted.
*/
static int
iocp_fetch_one(struct iocp_loop_ctx *ctx, DWORD ms, struct iocp_event **iev,
	       short *what)
{
	int rv;
	OVERLAPPED *olp;
	DWORD bytes;
	ULONG_PTR key;
	struct iocp_overlapped *iol;
	int canceled = 0;

	rv = GetQueuedCompletionStatus(ctx->iocp, &bytes, &key, &olp, ms);

	if (!rv) {
		DWORD err = GetLastError();
		if (err == WAIT_TIMEOUT)
			return 0;
		else if (err == ERROR_OPERATION_ABORTED)
			canceled = 1;
	}

	if (!olp)
		return -1;

	iol = EVUTIL_UPCAST(olp, struct iocp_overlapped, ol);
	*iev = iol->ev;

	if (canceled)
		*what = 0;
	else if (iol == &(*iev)->ord)
		*what = EV_READ;
	else
		*what = EV_WRITE;

	return 1;
}

/** Activate an event and decrement its reference count.

    This tells Libevent to run callbacks if the operation wasn't cancelled
    (what is not zero). Unconnected sockets are also checked to see if
    they are now connected and ready to be polled using overlapped
    operations.
 
    @param base The event base.
    @param iev The IOCP event.
    @param what The type of event.
*/
static void
iocp_active(struct event_base *base, struct iocp_event *iev, short what)
{
	struct iocp_loop_ctx *ctx = base->evbase;

	if (!iev)
		return;

	if (what) {
		if (what & EV_READ)
			iev->flags &= ~IOCP_LAUNCHED_READ;
		else {
			iev->flags &= ~IOCP_LAUNCHED_WRITE;
			/* Only remove the socket from the poll thread if the
			   connection succeeded. The user might try to connect
			   again if a failure occurred. */
			if (iev->type == IOCP_SOCK_UNCONNECTED &&
			    evutil_socket_finished_connecting(iev->sock) == 1) {
				poll_thread_pool_del_event(ctx, iev);
				iev->type = IOCP_SOCK_OVERLAPPED;
			}
		}

		evmap_io_active(base, iev->sock, what);
		ctx->nactivated++;

		if (iev->type == IOCP_SOCK_OVERLAPPED)
			overlapped_queue_push(ctx, iev);
	}

	iocp_event_decref(iev);
}

/** Activate any queued completion packets.

    @param base The event base.
    @return 0 on success, -1 on failure.
*/
static int
iocp_flush(struct event_base *base)
{
	struct iocp_loop_ctx *ctx = base->evbase;
	int rv;
	struct iocp_event *iev;
	short what;

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	while ((rv = iocp_fetch_one(ctx, 0, &iev, &what)) == 1) {
		EVBASE_ACQUIRE_LOCK(base, th_base_lock);
		iocp_active(base, iev, what);
		EVBASE_RELEASE_LOCK(base, th_base_lock);
	}

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	return rv;
}

/* Libevent slots */

/** Init IOCP backend context

    @param base The event base.
    @return IOCP context.
*/
static void *
iocp_loop_init(struct event_base *base)
{
	HANDLE iocp;
	struct iocp_loop_ctx *ctx;

	iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
	if (iocp == NULL)
		return NULL;

	ctx = mm_calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	TAILQ_INIT(&ctx->notify_pool);
	TAILQ_INIT(&ctx->overlapped_queue);
	ctx->iocp = iocp;
	ctx->base = base;

	evsig_init(base);

	return ctx;
}

/** Run overlapped operations and activate completion packets.

    @param tv Wait time.
    @param base The event base.
    @return 0 on success, -1 on failure.
*/
static int
iocp_loop_dispatch(struct event_base *base, struct timeval *tv)
{
	struct iocp_loop_ctx *ctx = base->evbase;
	struct iocp_event *iev;
	int rv = 0;
	short what;
	DWORD ms = INFINITE;

	overlapped_queue_run_all(ctx);
	// XXX err code

	if (iocp_flush(base) < 0)
		return -1;

	if (ctx->nactivated)
		return 0;

	if (tv)
		ms = tv->tv_sec * 1000 + (tv->tv_usec + 999) / 1000;

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	rv = iocp_fetch_one(ctx, ms, &iev, &what);

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	if (rv == 1) {
		iocp_active(base, iev, what);
		rv = 0;
	}

	if (!ctx->nactivated || base->sig.evsig_caught)
		evsig_process(base);

	return rv;
}

/** Start monitoring a socket for I/O event(s)

    @param base The event base.
    @param fd The socket.
    @param old Old events.
    @param events New events.
    @param _iev IOCP event.
    @return 0 on success, -1 on failure.
*/
// XXX may be able to use changelist stuff here instead 
static int
iocp_loop_add(struct event_base *base, evutil_socket_t fd, short old,
	      short events, void *_iev)
{
	struct iocp_loop_ctx *ctx = base->evbase;
	struct iocp_event **ievp = _iev;
	struct iocp_event *iev;
	
	EVUTIL_ASSERT(events);

	if (!*ievp) {
		*ievp = iocp_event_new(ctx, fd);
		if (*ievp == NULL)
			return -1;
	}

	iev = *ievp;

	if (events & EV_READ) {
		EVUTIL_ASSERT(!(iev->flags & IOCP_POLL_READ));
		iev->flags |= IOCP_POLL_READ;
	}
	if (events & EV_WRITE) {
		EVUTIL_ASSERT(!(iev->flags & IOCP_POLL_WRITE));
		iev->flags |= IOCP_POLL_WRITE;
	}

	if (iev->type == IOCP_SOCK_OVERLAPPED) {
		if (!(iev->flags & IOCP_QUEUED))
			overlapped_queue_push(ctx, iev);
	} else {
	       	if (!iev->poll_thr)
			poll_thread_pool_add_event(ctx, iev);
		iocp_event_update_event_selection(iev);
	}	

	return 0;
}

/** Stop monitoring event(s)

    @param base The event base.
    @param fd The socket.
    @param old Old events.
    @param events New events.
    @param _iev IOCP event.
    @return 0 on success, -1 on failure.
*/
// XXX may be able to use changelist stuff here instead 
static int
iocp_loop_del(struct event_base *base, evutil_socket_t fd, short old,
	      short events, void *_iev)
{
	struct iocp_loop_ctx *ctx = base->evbase;
	struct iocp_event **ievp = _iev;
	struct iocp_event *iev;

	if (!*ievp)
		return 0;

	iev = *ievp;

	if (events & EV_READ) {
		EVUTIL_ASSERT(iev->flags & IOCP_POLL_READ);
		iev->flags &= ~IOCP_POLL_READ;
	}
	if (events & EV_WRITE) {
		EVUTIL_ASSERT(iev->flags & IOCP_POLL_WRITE);
		iev->flags &= ~IOCP_POLL_WRITE;
	}

	/* Remove this iocp event if we're finished with it. */
	if ((iev->flags & (IOCP_POLL_READ | IOCP_POLL_WRITE)) == 0) {
		/* XXX if EVBASE_IN_THREAD(base), we may be able to run
		 * CancelIo() directly */
		if (iev->type == IOCP_SOCK_OVERLAPPED)
			overlapped_queue_cancel(ctx, iev);
		*ievp = NULL;
		iocp_event_decref(iev);
	}

	return 0;
}

/** Destroy IOCP backend context

    @param base The event base.
*/
static void
iocp_loop_dealloc(struct event_base *base)
{
	struct iocp_loop_ctx *ctx = base->evbase;

	poll_thread_pool_destroy(ctx);
	CloseHandle(ctx->iocp);
	// EVUTIL_ASSERT(!TAILQ_FIRST(&ctx->overlapped_queue));
	mm_free(ctx);
}

const struct eventop iocpops = {
	"iocp",
	iocp_loop_init,
	iocp_loop_add,
	iocp_loop_del,
	iocp_loop_dispatch,
	iocp_loop_dealloc,
	0, /* doesn't need_reinit */
	EV_FEATURE_O1,
	sizeof(struct iocp_event **),
};
