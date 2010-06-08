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

#include "event-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

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
#include "util-internal.h"

/* Hybrid win32 backend.
 *
 * This backend allows monitoring of both win32 handles and sockets. Two
 * variations of this backend are provided: "hybridselect" and
 * "hybrideventselect". The former uses select for monitoring sockets for
 * compatibility, and the latter uses WSAEventSelect/WaitForObjects. The
 * behavior of the latter is incompatible with select, though it may scale
 * a bit better in some cases. In particular, write events for a socket
 * are triggered again only after a send operation returns WSAEWOULDBLOCK
 * and room in the socket's buffer becomes available. Both "select" and
 * "eventselect" allow monitoring of handles and sockets simultaneously.
 * 
 * A pool of "poll threads" running WaitForMultipleObjects is used to
 * monitor handles (and sockets with WSAEventSelect). For the "select"
 * backend, a "poll compatability thread" is launched to dispatch select
 * as needed. All event notifications generated from the worker threads
 * are aggregated in the backend's IOCP queue, and the hybrid dispatch
 * function dispatches the results.
 *
 */

#define POLL_COMPAT_DISPATCH_DONE 0xfff

struct hybrid_loop_ctx;
struct hybrid_event;
struct poll_thread;
struct poll_compat_thread;

/** The type of object being monitored. Socket or win32 handle. */
enum hybrid_event_type {
	HYBRID_SOCK_UDP,
	HYBRID_SOCK_LISTENER,
	HYBRID_SOCK_UNCONNECTED,
	HYBRID_SOCK_TCP,
	HYBRID_HANDLE,
};

/** Hybrid event flags. */
enum hybrid_event_flags {
	HYBRID_EOF = 1<<0,
	HYBRID_POLL_READ = 1<<1,
	HYBRID_POLL_WRITE = 1<<2,
	HYBRID_GOT_READ = 1<<3,
	HYBRID_GOT_WRITE = 1<<4,
	HYBRID_CANCEL = 1<<5,
};

/** An event tracked by the hybrid backend.  */
struct hybrid_event {
	/** Links for the overlapped queue. */
	TAILQ_ENTRY(hybrid_event) next;

	/** The type of the socket. */
	ev_uint8_t type;

	/** Flags. */
	ev_uint8_t flags;

	/** Socket descriptor. */
	evutil_socket_t sock;

	/** Handle of the event object for use with WSAEventSelect. */
	HANDLE poll_event;

	/** Pointer to the poll thread this hybrid event belongs to.
	    We store this in the event object so we don't have to
	    search through the thread pool to find it when we want
	    to remove the event from the poll thread */
	struct poll_thread *poll_thr;

	/** Reference count. */
	int refcnt;

	/** Read event for poll compat select fallback. */
	struct event compat_rd;

	/** Write event for poll compat select fallback. */
	struct event compat_wr;

	/** Hybrid context. */
	struct hybrid_loop_ctx *ctx;
};

/** Poll thread operation type.  */
enum poll_thread_op_type {
	POLL_OP_ADD,
	POLL_OP_DEL,
	POLL_OP_STOP
};

/** Poll thread op data. */
struct poll_thread_op {
	/** Poll thread to run the operation on. */
	struct poll_thread *thr;
	
	/** The type of operation to run. */
	enum poll_thread_op_type type;

	/** The index in the event array to operate on. */
	size_t index;

	/** The handle to add to the event array. */
	HANDLE handle;
};

/**
 * "Poll thread" used to poll handles and sockets with
 * WSAEventSelect/WaitForObjects. Multiple threads are used
 * in a pool when more than MAXIMUM_WAIT_OBJECTS objects are
 * being monitored.
 */
struct poll_thread {
	/** Thread pool links. */
	TAILQ_ENTRY(poll_thread) next;

	/** Handle of the thread. */
	HANDLE handle;

	/** Thread is stopping */
	int stopping;

	/** The hybrid backend context. */
	struct hybrid_loop_ctx *ctx;

	/** The number of free slots in this thread. */
	size_t nfree;

	/** Windows event objects to wait on. */
	HANDLE waitlist[MAXIMUM_WAIT_OBJECTS];

	/** Pre-allocated event objects for event-select */
	HANDLE iolist[MAXIMUM_WAIT_OBJECTS];

	/** Hybrid backend events being monitored. */
	struct hybrid_event *evlist[MAXIMUM_WAIT_OBJECTS];
};

/**
 * Poll compatibility thread operation.
 */
enum poll_compat_thread_op {
	POLL_COMPAT_OP_NONE,
	POLL_COMPAT_OP_DISPATCH,
	POLL_COMPAT_OP_STOP
};

/**
 * Since behavior of WSAEventSelect/WaitForObjects is not always desirable,
 * we need a "poll compatability thread" for a fallback to poll sockets with
 * select. This runs in a separate thread so that win32 handles can be
 * monitored as well.
 */
struct poll_compat_thread {
	/** Handle of the thread. */
	HANDLE handle;

	/** Provide timeout to dispatch? */
	int do_select_wait;

	/** Timeout value. */
	struct timeval select_wait;

	/** Libevent base using select. */
	struct event_base *select_base;

	/** Operation for the thread to execute. */
	enum poll_compat_thread_op current_op;
};

/** The context for the hybrid backend */
struct hybrid_loop_ctx {
	/** Handle of the IOCP. */
	HANDLE iocp;
	
	/** Poll thread pool. */
	TAILQ_HEAD(poll_thread_list, poll_thread) notify_pool;

	/** Boolean. Is select running? */
	int compat_dispatch;

	/** Poll compatibility thread. */
	struct poll_compat_thread *pct;

	/** Closed sockets to generate read events for. */
	TAILQ_HEAD(hybrid_event_list, hybrid_event) closed_sockets;

	/** Number of events activated in a call to hybrid_loop_dispatch() */
	size_t nactivated;

	/** The event base; poll threads need access to the base lock. */
	struct event_base *base;
};

/** Determine what we're monitoring.

    @param sock The socket (or handle).
    @return type of socket/handle on success, or -1 on failure.
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
		return HYBRID_HANDLE;
	if (intval == SOCK_DGRAM)
		return HYBRID_SOCK_UDP;

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
		return HYBRID_SOCK_LISTENER;

	/* Is this socket not connected yet? */
	len = sizeof(DWORD);
	dwval = 0;
	rv = getsockopt(sock, SOL_SOCKET, SO_CONNECT_TIME, (char*)&dwval, &len);
	if (rv == SOCKET_ERROR || dwval == (DWORD)-1)
		return HYBRID_SOCK_UNCONNECTED;

	return HYBRID_SOCK_TCP;
}

/** Allocate a new hybrid event structure.

    @param ctx The hybrid backend context.
    @param sock The socket to monitor.
*/
static struct hybrid_event *
hybrid_event_new(struct hybrid_loop_ctx *ctx, evutil_socket_t sock)
{
	int type;
	struct hybrid_event *hev;

	type = get_sock_type(sock);
	if (type < 0)
		return NULL;

	hev = mm_calloc(1, sizeof(*hev));
	if (!hev)
		return NULL;

	hev->sock = sock;
	hev->type = type;
	hev->refcnt = 1;
	hev->ctx = ctx;

	return hev;
}

/** Add a reference to an hybrid event object.

    @param hev The hybrid event object.
*/
static void
hybrid_event_incref(struct hybrid_event *hev)
{
	hev->refcnt++;
}

/** Remove a reference to an hybrid event object.

    @param hev The hybrid event object.
*/
static void
hybrid_event_decref(struct hybrid_event *hev)
{
	if (--hev->refcnt <= 0) {
		EVUTIL_ASSERT(hev->poll_thr == NULL);
		mm_free(hev);
	}
}

/**
 * Execute a poll thread operation.
 *
 * @param _op Operation type and arguments.
 */
static VOID CALLBACK
poll_thread_run_op(ULONG_PTR _op)
{
	struct poll_thread_op *op = UlongToPtr(_op);
	size_t i;

	switch (op->type) {
	case POLL_OP_ADD:
		i = op->index;
		op->thr->waitlist[i] = op->handle;
		break;
	case POLL_OP_DEL:
		i = op->index;
		op->thr->waitlist[i] = op->thr->iolist[i];
		break;
	case POLL_OP_STOP:
		op->thr->stopping = 1;
		break;
	}

	mm_free(op);
}

/**
 * Tell the poll thread to stop.
 *
 * @param thr The poll thread.
 * @return 0 on success, -1 on failure.
 */
static int
poll_thread_op_stop(struct poll_thread *thr)
{
	struct poll_thread_op *op;

	op = mm_calloc(1, sizeof(*op));
	if (!op)
		return -1;
	op->thr = thr;
	op->type = POLL_OP_STOP;
	if (QueueUserAPC(poll_thread_run_op, thr->handle, PtrToUlong(op)) == 0)
		return -1;

	return 0;
}

/**
 * Add a handle to a poll thread.
 *
 * @param thr The poll thread.
 * @param index Event slot.
 * @param h The handle to monitor.
 * @return 0 on success, -1 on failure.
 */
static int
poll_thread_op_add_handle(struct poll_thread *thr, size_t index, HANDLE h)
{
	struct poll_thread_op *op;

	op = mm_calloc(1, sizeof(*op));
	if (!op)
		return -1;
	op->thr = thr;
	op->type = POLL_OP_ADD;
	op->index = index;
	op->handle = h;
	if (QueueUserAPC(poll_thread_run_op, thr->handle, PtrToUlong(op)) == 0)
		return -1;

	return 0;
}

/**
 * Remove a handle from a poll thread.
 *
 * @param thr The poll thread.
 * @param index Event slot.
 * @return 0 on success, -1 on failure.
 */
static int
poll_thread_op_del_handle(struct poll_thread *thr, size_t index)
{
	struct poll_thread_op *op;

	op = mm_calloc(1, sizeof(*op));
	if (!op)
		return -1;
	op->thr = thr;
	op->type = POLL_OP_DEL;
	op->index = index;
	if (QueueUserAPC(poll_thread_run_op, thr->handle, PtrToUlong(op)) == 0)
		return -1;

	return 0;
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
		CloseHandle(poll_thr->iolist[i]);
	}

	mm_free(poll_thr);
}

/** Allocate a new poll thread.

    @param ctx The hybrid backend context.
    @return A new poll thread object.
*/
static struct poll_thread *
poll_thread_new(struct hybrid_loop_ctx *ctx)
{
	size_t i;
	struct poll_thread *ret;

	ret = mm_calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	ret->nfree = MAXIMUM_WAIT_OBJECTS;
	ret->ctx = ctx;

	for (i = 0; i < MAXIMUM_WAIT_OBJECTS; ++i) {
		HANDLE h = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (h == NULL) {
			poll_thread_destroy(ret);
			return NULL;
		}

		ret->waitlist[i] = h;
		ret->iolist[i] = h;
	}	

	return ret;
}

/** Set the events a poll thread should monitor.
 
    This translates the socket type and flags into flags
    for WSAEventSelect(). Call this each time the user changes
    the events they want to poll for.

    @param hev The hybrid event.
    @return 0 on success, -1 on failure.
*/
static int
hybrid_event_update_event_selection(struct hybrid_event *hev)
{
	long nev = 0;

	if (!hev->poll_event || !hev->poll_thr || hev->type == HYBRID_HANDLE)
		return 0;

	switch (hev->type) {
	case HYBRID_SOCK_TCP:
	case HYBRID_SOCK_UDP:
		if (hev->flags & HYBRID_POLL_READ)
			nev |= FD_READ | FD_CLOSE;
		if (hev->flags & HYBRID_POLL_WRITE)
			nev |= FD_WRITE | FD_CLOSE;
		break;
	case HYBRID_SOCK_LISTENER:
		if (hev->flags & HYBRID_POLL_READ)
			nev |= FD_ACCEPT;
		break;
	case HYBRID_SOCK_UNCONNECTED:
		nev |= FD_CONNECT;
		break;
	default:
		abort();
	}

	/* XXX It seems we can use WSAEventSelect() when a poll thread
	   is waiting on the event object. */
	if (WSAEventSelect(hev->sock, hev->poll_event, nev) == SOCKET_ERROR)
		return -1;

	return 0;
}

/** Post an event notification to the IOCP, noticing when TCP sockets
    become connected.

    This is a helper for the thread loop. The event base should be locked.

    @param poll_thr The poll thread.
    @param i The index of the event.
*/
static void
poll_thread_post(struct poll_thread *poll_thr, DWORD i)
{
	WSANETWORKEVENTS what;
	struct hybrid_event *hev;
	int ev = 0;

	hev = poll_thr->evlist[i];
	if (!hev)
		return;

	EVUTIL_ASSERT(!(hev->flags & HYBRID_CANCEL));

	// XXX this may fill the queue with notifications if the handle's
	// status isn't reset.
	if (hev->type == HYBRID_HANDLE) {
		hybrid_event_incref(hev);
		PostQueuedCompletionStatus(poll_thr->ctx->iocp, 0,
				EV_READ | EV_WRITE, (OVERLAPPED*)hev);
		return;
	}

	// XXX handle error
	WSAEnumNetworkEvents(hev->sock, NULL, &what);

	if (what.lNetworkEvents & (FD_CONNECT | FD_WRITE)) {
		ev |= EV_WRITE;
	} else {
		ev |= EV_READ;
	}

	if ((what.lNetworkEvents & FD_CONNECT) &&
	    hev->type == HYBRID_SOCK_UNCONNECTED &&
	    evutil_socket_finished_connecting(hev->sock) == 1) {
		hev->type = HYBRID_SOCK_TCP;
		hybrid_event_update_event_selection(hev);
	}

	hybrid_event_incref(hev);

	// XXX handle error
	PostQueuedCompletionStatus(poll_thr->ctx->iocp, 0, ev,
			(OVERLAPPED*)hev);

	if (!(hev->flags & HYBRID_EOF) && (what.lNetworkEvents & FD_CLOSE)) {
		hybrid_event_incref(hev);
		hev->flags |= HYBRID_EOF;
		TAILQ_INSERT_TAIL(&poll_thr->ctx->closed_sockets, hev, next);
	}
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
		do {
			rv = WaitForMultipleObjectsEx(
					MAXIMUM_WAIT_OBJECTS,
					poll_thr->waitlist,
					FALSE,
					INFINITE,
					TRUE);

			if (rv == WAIT_FAILED) {
				// XXX
				return 0;
			}
			if (poll_thr->stopping)
				return 0;
		} while (rv == WAIT_IO_COMPLETION);

		rv -= WAIT_OBJECT_0;
		EVUTIL_ASSERT(rv >= 0 && rv < MAXIMUM_WAIT_OBJECTS);
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

	poll_thread_op_stop(poll_thr);
	WaitForSingleObject(poll_thr->handle, INFINITE);
	CloseHandle(poll_thr->handle);
	poll_thr->handle = NULL;
}

/** Add an event to the poll thread.

    @param poll_thr The poll thread.
    @param hev The hybrid event.
    @return 1 if succesfully added, 0 if already full.
*/
static int
poll_thread_add_event(struct poll_thread *poll_thr, struct hybrid_event *hev)
{
	size_t i;

	EVUTIL_ASSERT(hev->poll_thr == NULL);

	if (!poll_thr->nfree)
		return 0;

	for (i = 0; i < MAXIMUM_WAIT_OBJECTS; ++i) {
		if (!poll_thr->evlist[i]) {
			hybrid_event_incref(hev);
			poll_thr->evlist[i] = hev;
			if (hev->type == HYBRID_HANDLE) {
				hev->poll_event = (HANDLE)hev->sock;
				poll_thread_op_add_handle(poll_thr, i,
						hev->poll_event);
			} else
				hev->poll_event = poll_thr->iolist[i];
			hev->poll_thr = poll_thr;
			poll_thr->nfree--;
			return 1;
		}
	}

	return 0;
}

/** Remove an event to the poll thread.

    @param poll_thr The poll thread.
    @param hev The hybrid event.
    @return 1 if succesfully removed, 0 not found.
*/
static int
poll_thread_del_event(struct poll_thread *poll_thr, struct hybrid_event *hev)
{
	size_t i;

	EVUTIL_ASSERT(hev->poll_thr != NULL);

	for (i = 0; i < MAXIMUM_WAIT_OBJECTS; ++i) {
		if (poll_thr->evlist[i] == hev) {
			poll_thr->evlist[i] = NULL;
			hev->poll_thr = NULL;
			hev->poll_event = NULL;
			if (hev->type == HYBRID_HANDLE)
				poll_thread_op_del_handle(poll_thr, i);
			else
				WSAEventSelect(hev->sock, NULL, 0);
			hybrid_event_decref(hev);
			poll_thr->nfree++;
			return 1;
		}
	}

	return 0;
}

/** Add an event to the poll thread pool.

    If all threads are full, add a new thread automatically.

    @param ctx The hybrid backend context.
    @param hev The hybrid event.
    @return 0 on success, -1 on failure.
*/
static int
poll_thread_pool_add_event(struct hybrid_loop_ctx *ctx, struct hybrid_event *hev)
{
	struct poll_thread *new_worker, *it;

	TAILQ_FOREACH(it, &ctx->notify_pool, next) {
		if (poll_thread_add_event(it, hev))
			return 0;
	}

	/* All workers are full, so add a new worker. */
	new_worker = poll_thread_new(ctx);
	if (!new_worker)
		return -1;
	if (poll_thread_start(new_worker) < 0 ||
	    !poll_thread_add_event(new_worker, hev)) {
		poll_thread_destroy(new_worker);
		return -1;
	}

	/* Add new threads to the front of the list so we can
	   fill them up without having to iterate to the back */
	TAILQ_INSERT_HEAD(&ctx->notify_pool, new_worker, next);

	return 0;
}

/** Remove an event from the poll event pool.
    
    @param ctx The hybrid backend context.
    @param hev The hybrid event.
    @return 0 on success, -1 on failure.
*/
static int
poll_thread_pool_del_event(struct hybrid_loop_ctx *ctx, struct hybrid_event *hev)
{
	/* XXX when is a good time to clean up unused worker threads? */

	poll_thread_del_event(hev->poll_thr, hev);

	return 0;
}

/** Stop and destroy all threads in the poll thread pool.

    @param ctx The hybrid backend context.
*/
static void
poll_thread_pool_destroy(struct hybrid_loop_ctx *ctx)
{
	struct poll_thread *it;

	while ((it = TAILQ_FIRST(&ctx->notify_pool)) != NULL) {
		TAILQ_REMOVE(&ctx->notify_pool, it, next);
		poll_thread_stop(it);
		poll_thread_destroy(it);
	}
}

/** Poll compat thread main loop.
 *
 *  @param _ctx Hybrid backend context.
 */
static unsigned __stdcall
poll_compat_thread_loop(void *_ctx)
{
	struct hybrid_loop_ctx *ctx = _ctx;

	while (1) {
		switch (ctx->pct->current_op) {
		case POLL_COMPAT_OP_DISPATCH:
			if (ctx->pct->do_select_wait)
				event_base_loopexit(ctx->pct->select_base,
						&ctx->pct->select_wait);
			event_base_loop(ctx->pct->select_base, EVLOOP_ONCE);
			PostQueuedCompletionStatus(ctx->iocp, 0,
					POLL_COMPAT_DISPATCH_DONE, NULL);
			break;
		case POLL_COMPAT_OP_STOP:
			return 0;
		case POLL_COMPAT_OP_NONE:
			break;
		default:
			abort();
		}

		if (SleepEx(INFINITE, TRUE) != WAIT_IO_COMPLETION)
			return 1;
	}

	return 0;
}

/** Allocate and start poll compat thread.
 *
 *  @param ctx Hybrid backend context.
 */
static void
poll_compat_thread_init(struct hybrid_loop_ctx *ctx)
{
	const char *method;
	struct poll_compat_thread *pct;
	struct event_config *cfg;
	HANDLE th;

	EVUTIL_ASSERT(ctx->pct == NULL);

	pct = mm_calloc(1, sizeof(*pct));
	if (!pct)
		return;

	cfg = event_config_new();
	if (!cfg)
		goto out;

	if (event_config_require_method(cfg, "win32") < 0)
		goto out;

	pct->select_base = event_base_new_with_config(cfg);
	if (!pct->select_base)
		goto out;

	event_config_free(cfg);
	method = event_base_get_method(pct->select_base);
	EVUTIL_ASSERT(!evutil_ascii_strcasecmp(method, "win32"));

	th = (HANDLE)_beginthreadex(NULL, 0,
			poll_compat_thread_loop, ctx, 0, NULL);
	if (!th)
		goto out;

	pct->current_op = POLL_COMPAT_OP_NONE;
	pct->handle = th;
	ctx->pct = pct;

	return;

out:
	if (cfg)
		event_config_free(cfg);
	if (pct->select_base)
		event_base_free(pct->select_base);
	mm_free(pct);
}

/** Libevent event callback for poll compat events.
 *
 *  @param fd socket.
 *  @param what Event type(s).
 *  @param _hev Hybrid event.
 */
static void
poll_compat_thread_event_cb(evutil_socket_t fd, short what, void *_hev)
{
	struct hybrid_event *hev = _hev;

	EVBASE_ACQUIRE_LOCK(hev->ctx->base, th_base_lock);
	hybrid_event_incref(hev);
	EVBASE_RELEASE_LOCK(hev->ctx->base, th_base_lock);
	PostQueuedCompletionStatus(hev->ctx->iocp, 0, what, _hev);
}

/** Tell the poll compat base to start monitoring event(s).
 *
 *  @param ctx Hybrid loop context.
 *  @param hev Hybrid event.
 *  @param what Event type(s).
 */
static void
poll_compat_thread_add_event(struct hybrid_loop_ctx *ctx,
		struct hybrid_event *hev, short what)
{
	hybrid_event_incref(hev);
	if (what & EV_READ) {
		event_assign(&hev->compat_rd, ctx->pct->select_base, hev->sock,
				what | EV_PERSIST, poll_compat_thread_event_cb,
				hev);
		event_add(&hev->compat_rd, NULL);
	}
	if (what & EV_WRITE) {
		event_assign(&hev->compat_wr, ctx->pct->select_base, hev->sock,
				what | EV_PERSIST, poll_compat_thread_event_cb,
				hev);
		event_add(&hev->compat_wr, NULL);
	}
}

/** Tell the poll compat base to stop monitoring event(s).
 *
 *  @param ctx Hybrid loop context.
 *  @param hev Hybrid event.
 *  @param what Event type(s).
 */
static void
poll_compat_thread_del_event(struct hybrid_loop_ctx *ctx,
		struct hybrid_event *hev, short what)
{
	if (what & EV_READ) {
		event_del(&hev->compat_rd);
		hybrid_event_decref(hev);
	}
	if (what & EV_WRITE) {
		event_del(&hev->compat_wr);
		hybrid_event_decref(hev);
	}
}

/** Windows APC to set the dispatch operation.
 *
 *  @param _pct Poll compat thread context.
 */
static VOID CALLBACK
poll_compat_thread_run_op_dispatch(ULONG_PTR _pct)
{
	struct poll_compat_thread *pct = UlongToPtr(_pct);
	pct->current_op = POLL_COMPAT_OP_DISPATCH;
}

/** Windows APC to set the stop operation.
 *
 *  @param _pct Poll compat thread context.
 */
static VOID CALLBACK
poll_compat_thread_run_op_stop(ULONG_PTR _pct)
{
	struct poll_compat_thread *pct = UlongToPtr(_pct);
	pct->current_op = POLL_COMPAT_OP_STOP;
}

/** Tell the poll compat thread to run dispatch.
 *
 *  @param ctx Hybrid backend context.
 *  @return 0 on success, -1 on failure.
 */
static int
poll_compat_thread_op_dispatch(struct hybrid_loop_ctx *ctx,
		const struct timeval *tv)
{
	EVUTIL_ASSERT(ctx->compat_dispatch == 0);

	ctx->pct->do_select_wait = 0;
	if (tv) {
		ctx->pct->do_select_wait = 1;
		memcpy(&ctx->pct->select_wait, tv, sizeof(*tv));
	}

	if (QueueUserAPC(poll_compat_thread_run_op_dispatch,
	    ctx->pct->handle, PtrToUlong(ctx->pct)) == 0)
		return -1;

	ctx->compat_dispatch = 1;

	return 0;
}

/** Tell the poll compat thread to quit.
 *
 *  @param ctx Hybrid backend context.
 *  @return 0 on success, -1 on failure.
 */
static int
poll_compat_thread_op_stop(struct hybrid_loop_ctx *ctx)
{
	if (QueueUserAPC(poll_compat_thread_run_op_stop,
	    ctx->pct->handle, PtrToUlong(ctx->pct)) == 0)
		return -1;
	
	return 0;
}

/** Stop and deallocate poll compatability thread.
 *
 *  @param ctx Hybrid backend context.
 */
static void
poll_compat_thread_destroy(struct hybrid_loop_ctx *ctx)
{
	if (!ctx->pct)
		return;
	event_base_loopbreak(ctx->pct->select_base);
	poll_compat_thread_op_stop(ctx);
	WaitForSingleObject(ctx->pct->handle, INFINITE);
	CloseHandle(ctx->pct->handle);
	event_base_free(ctx->pct->select_base);
	mm_free(ctx->pct);
	ctx->pct = NULL;
}

/** Attempt to fetch a single event from the queue.

    The base lock needn't be held. When an event object is fetched, a
    reference to the event is still held. Use hybrid_handle_event() to
    activate the event and remove the reference. *hev is NULL when
    there is notice of the compat dispatch's completion.

    @param ctx The hybrid backend context.
    @param ms The maximum amount of time to wait for an event.
    @param hev The fetched event.
    @param what The event type.
    @return -1 error, 0 timeout, 1 dispatched or aborted.
*/
static int
hybrid_fetch_one_event(struct hybrid_loop_ctx *ctx, DWORD ms,
		 struct hybrid_event **hev, short *what)
{
	int rv;
	OVERLAPPED *olp;
	DWORD bytes;
	ULONG_PTR key;

	rv = GetQueuedCompletionStatus(ctx->iocp, &bytes, &key, &olp, ms);

	if (!rv) {
		DWORD err = GetLastError();
		if (err == WAIT_TIMEOUT)
			return 0;
	}

	*hev = (struct hybrid_event *)olp;
	*what = key;

	return 1;
}

/** Activate an event or note that select dispatch has completed.

    If hev is not NULL, this tells Libevent to call any callbacks
    associated with the event.

    @param base The event base.
    @param hev The hybrid event.
    @param what The type of event.
*/
static void
hybrid_handle_event(struct event_base *base, struct hybrid_event *hev,
		short what)
{
	struct hybrid_loop_ctx *ctx = base->evbase;

	if (what == POLL_COMPAT_DISPATCH_DONE) {
		EVUTIL_ASSERT(ctx->compat_dispatch);
		ctx->compat_dispatch = 0;
	}

	if (!hev)
		return;

	if (!(hev->flags & HYBRID_CANCEL)) {
		evmap_io_active(base, hev->sock, what);
		ctx->nactivated++;
	}

	hybrid_event_decref(hev);
}

/** Activate any queued completion packets and note closed sockets.

    @param base The event base.
    @return 0 on success, -1 on failure.
*/
static int
hybrid_flush_queue(struct event_base *base)
{
	struct hybrid_loop_ctx *ctx = base->evbase;
	int rv;
	struct hybrid_event *hev;
	short what;

	TAILQ_FOREACH(hev, &ctx->closed_sockets, next) {
		evmap_io_active(base, hev->sock, EV_READ);
		ctx->nactivated++;
	}

	while ((rv = hybrid_fetch_one_event(ctx, 0, &hev, &what)) == 1) {
		hybrid_handle_event(base, hev, what);
	}

	return rv;
}

/** Run dispatch in the poll compat thread, and wait for it to complete.
 *
 *  @param base Lbevent base.
 *  @param tv Wait time.
 */
static int
hybrid_compat_dispatch(struct event_base *base,
		const struct timeval *tv)
{
	struct hybrid_loop_ctx *ctx = base->evbase;
	int rv;
	struct hybrid_event *hev;
	short what;

	poll_compat_thread_op_dispatch(ctx, tv);

	EVBASE_RELEASE_LOCK(base, th_base_lock);
	while (ctx->compat_dispatch &&
	       (rv = hybrid_fetch_one_event(ctx, INFINITE, &hev, &what)) == 1) {
		EVBASE_ACQUIRE_LOCK(base, th_base_lock);
		hybrid_handle_event(base, hev, what);
		EVBASE_RELEASE_LOCK(base, th_base_lock);
	}
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	return rv;
}

/** Allocate hybrid backend context.

    @param base The event base.
    @return Hybrid backend context.
*/
static struct hybrid_loop_ctx *
hybrid_loop_ctx_new(struct event_base *base)
{
	HANDLE iocp;
	struct hybrid_loop_ctx *ctx;

	iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
	if (iocp == NULL)
		return NULL;

	ctx = mm_calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	TAILQ_INIT(&ctx->notify_pool);
	TAILQ_INIT(&ctx->closed_sockets);
	ctx->iocp = iocp;
	ctx->base = base;
	evsig_init(base);

	return ctx;
}

/* Libevent slots */

/** Init hybrid backend context, using select to monitor sockets.

    @param base The event base.
    @return Hybrid backend context.
*/
static void *
hybrid_loop_init_select(struct event_base *base)
{
	struct hybrid_loop_ctx *ctx;

	ctx = hybrid_loop_ctx_new(base);
	if (ctx)
		poll_compat_thread_init(ctx);

	return ctx;
}

/** Init hybrid backend context, using EventSelect to monitor sockets.

    @param base The event base.
    @return Hybrid backend context.
*/
static void *
hybrid_loop_init_evsel(struct event_base *base)
{
	return hybrid_loop_ctx_new(base);
}

/** Dispatch hybrid backend events.

    @param tv Maximum time to wait.
    @param base The event base.
    @return 0 on success, -1 on failure.
*/
static int
hybrid_loop_dispatch(struct event_base *base, struct timeval *tv)
{
	struct hybrid_loop_ctx *ctx = base->evbase;
	struct hybrid_event *hev;
	int rv = 0;
	short what;
	DWORD ms = INFINITE;

	ctx->nactivated = 0;

	if (ctx->pct) {
		hybrid_compat_dispatch(base, tv);
	} else {
		if (hybrid_flush_queue(base) < 0)
			return -1;

		if (ctx->nactivated)
			return 0;

		if (tv) {
			long msec = evutil_tv_to_msec(tv);
			if (msec < 0)
				msec = LONG_MAX;
			ms = msec;
		}

		EVBASE_RELEASE_LOCK(base, th_base_lock);

		rv = hybrid_fetch_one_event(ctx, ms, &hev, &what);

		EVBASE_ACQUIRE_LOCK(base, th_base_lock);

		if (rv == 1) {
			hybrid_handle_event(base, hev, what);
			rv = 0;
		}
	}

	if (!ctx->nactivated || base->sig.evsig_caught)
		evsig_process(base);

	return rv;
}

/** Start monitoring a socket or handle for events.

    @param base The event base.
    @param fd The socket.
    @param old Old events.
    @param events New events.
    @param _hev Hybrid event.
    @return 0 on success, -1 on failure.
*/
// XXX may be able to use changelist stuff here instead 
static int
hybrid_loop_add(struct event_base *base, evutil_socket_t fd, short old,
	      short events, void *_hev)
{
	struct hybrid_loop_ctx *ctx = base->evbase;
	struct hybrid_event **hevp = _hev;
	struct hybrid_event *hev;
	
	EVUTIL_ASSERT(events);

	if (!*hevp) {
		/* It'd be nice to allocate hybrid events together with the
		 * parent structure, but that would lead to problems if an
		 * event was deallocated while pending notifications were still
		 * queued in the IOCP. There's no way to remove stuff from an
		 * IOCP without fetching it. */
		*hevp = hybrid_event_new(ctx, fd);
		if (*hevp == NULL)
			return -1;
	}

	hev = *hevp;

	if (events & EV_READ) {
		EVUTIL_ASSERT(!(hev->flags & HYBRID_POLL_READ));
		hev->flags |= HYBRID_POLL_READ;
	}
	if (events & EV_WRITE) {
		EVUTIL_ASSERT(!(hev->flags & HYBRID_POLL_WRITE));
		hev->flags |= HYBRID_POLL_WRITE;
	}

	if (ctx->pct && hev->type != HYBRID_HANDLE) {
		poll_compat_thread_add_event(ctx, hev, events);
	} else {
		if (!hev->poll_thr)
			poll_thread_pool_add_event(ctx, hev);
		hybrid_event_update_event_selection(hev);
	}

	return 0;
}

/** Stop monitoring event(s)

    @param base The event base.
    @param fd The socket.
    @param old Old events.
    @param events New events.
    @param _hev hybrid event.
    @return 0 on success, -1 on failure.
*/
// XXX may be able to use changelist stuff here instead 
static int
hybrid_loop_del(struct event_base *base, evutil_socket_t fd, short old,
	      short events, void *_hev)
{
	struct hybrid_loop_ctx *ctx = base->evbase;
	struct hybrid_event **hevp = _hev;
	struct hybrid_event *hev;

	if (!*hevp)
		return 0;

	hev = *hevp;

	if (events & EV_READ) {
		EVUTIL_ASSERT(hev->flags & HYBRID_POLL_READ);
		hev->flags &= ~HYBRID_POLL_READ;
	}
	if (events & EV_WRITE) {
		EVUTIL_ASSERT(hev->flags & HYBRID_POLL_WRITE);
		hev->flags &= ~HYBRID_POLL_WRITE;
	}

	/* Remove this hybrid event if we're finished with it. */
	if (ctx->pct && hev->type != HYBRID_HANDLE) {
		poll_compat_thread_del_event(ctx, hev, events);
	} else if ((hev->flags & (HYBRID_POLL_READ | HYBRID_POLL_WRITE)) == 0) {
		*hevp = NULL;
		if (hev->flags & HYBRID_EOF) {
			hev->flags &= ~HYBRID_EOF;
			TAILQ_REMOVE(&ctx->closed_sockets, hev, next);
			hybrid_event_decref(hev);
		}
		hev->flags |= HYBRID_CANCEL;
		poll_thread_pool_del_event(ctx, hev);
		hybrid_event_decref(hev);
	}

	return 0;
}

/** Clean up and destroy hybrid backend context.

    @param base The event base.
*/
static void
hybrid_loop_dealloc(struct event_base *base)
{
	struct hybrid_loop_ctx *ctx = base->evbase;

	poll_compat_thread_destroy(ctx);
	poll_thread_pool_destroy(ctx);
	CloseHandle(ctx->iocp);
	mm_free(ctx);
}

const struct eventop hybridselectops = {
	"hybridselect",
	hybrid_loop_init_select,
	hybrid_loop_add,
	hybrid_loop_del,
	hybrid_loop_dispatch,
	hybrid_loop_dealloc,
	0, /* doesn't need_reinit */
	EV_FEATURE_WINHANDLES,
	sizeof(struct hybrid_event **),
};

const struct eventop hybrideventselectops = {
	"hybrideventselect",
	hybrid_loop_init_evsel,
	hybrid_loop_add,
	hybrid_loop_del,
	hybrid_loop_dispatch,
	hybrid_loop_dealloc,
	0, /* doesn't need_reinit */
	EV_FEATURE_WINHANDLES | EV_FEATURE_O1,
	sizeof(struct hybrid_event **),
};
