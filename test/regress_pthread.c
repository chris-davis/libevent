/*
 * Copyright (c) 2007-2010 Niels Provos and Nick Mathewson
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

#include "event2/event-config.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _EVENT_HAVE_PTHREADS
#include <pthread.h>
#elif defined(WIN32)
#include <process.h>
#endif
#include <assert.h>

#include "event2/util.h"
#include "event2/event.h"
#include "event2/event_struct.h"
#include "event2/thread.h"
#include "evthread-internal.h"
#include "regress.h"
#include "tinytest_macros.h"

#ifdef _EVENT_HAVE_PTHREADS
#define THREAD_T pthread_t
#define THREAD_FN void *
#define THREAD_RETURN() return (NULL)
#define THREAD_START(threadvar, fn, arg) \
	pthread_create(&(threadvar), NULL, fn, arg)
#define THREAD_JOIN(th) pthread_join(th, NULL)
#else
#define THREAD_T HANDLE
#define THREAD_FN unsigned __stdcall
#define THREAD_RETURN() return (0)
#define THREAD_START(threadvar, fn, arg) do {		\
	uintptr_t threadhandle = _beginthreadex(NULL,0,fn,(arg),0,NULL); \
	(threadvar) = (HANDLE) threadhandle; \
	} while (0)
#define THREAD_JOIN(th) WaitForSingleObject(th, INFINITE)
#endif

struct cond_wait {
	void *lock;
	void *cond;
};

static void
wake_all_timeout(evutil_socket_t fd, short what, void *arg)
{
	struct cond_wait *cw = arg;
	EVLOCK_LOCK(cw->lock, 0);
	EVTHREAD_COND_BROADCAST(cw->cond);
	EVLOCK_UNLOCK(cw->lock, 0);

}

static void
wake_one_timeout(evutil_socket_t fd, short what, void *arg)
{
	struct cond_wait *cw = arg;
	EVLOCK_LOCK(cw->lock, 0);
	EVTHREAD_COND_SIGNAL(cw->cond);
	EVLOCK_UNLOCK(cw->lock, 0);
}

#define NUM_THREADS	100
#define NUM_ITERATIONS  100
void *count_lock;
static int count;

static THREAD_FN
basic_thread(void *arg)
{
	struct cond_wait cw;
	struct event_base *base = arg;
	struct event ev;
	int i = 0;

	EVTHREAD_ALLOC_LOCK(cw.lock, 0);
	EVTHREAD_ALLOC_COND(cw.cond);
	assert(cw.lock);
	assert(cw.cond);

	evtimer_assign(&ev, base, wake_all_timeout, &cw);
	for (i = 0; i < NUM_ITERATIONS; i++) {
		struct timeval tv;
		evutil_timerclear(&tv);
		tv.tv_sec = 0;
		tv.tv_usec = 3000;

		EVLOCK_LOCK(cw.lock, 0);
		/* we need to make sure that event does not happen before
		 * we get to wait on the conditional variable */
		assert(evtimer_add(&ev, &tv) == 0);

		assert(EVTHREAD_COND_WAIT(cw.cond, cw.lock) == 0);
		EVLOCK_UNLOCK(cw.lock, 0);

		EVLOCK_LOCK(count_lock, 0);
		++count;
		EVLOCK_UNLOCK(count_lock, 0);
	}

	/* exit the loop only if all threads fired all timeouts */
	EVLOCK_LOCK(count_lock, 0);
	if (count >= NUM_THREADS * 100)
		event_base_loopexit(base, NULL);
	EVLOCK_UNLOCK(count_lock, 0);

	EVTHREAD_FREE_LOCK(cw.lock, 0);
	EVTHREAD_FREE_COND(cw.cond);

	THREAD_RETURN();
}

static void
thread_basic(void *arg)
{
	THREAD_T threads[NUM_THREADS];
	struct event ev;
	struct timeval tv;
	int i;
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;

	EVTHREAD_ALLOC_LOCK(count_lock, 0);
	tt_assert(count_lock);

	tt_assert(base);
	if (evthread_make_base_notifiable(base)<0) {
		tt_abort_msg("Couldn't make base notifiable!");
	}

	for (i = 0; i < NUM_THREADS; ++i)
		THREAD_START(threads[i], basic_thread, base);

	evtimer_assign(&ev, base, NULL, NULL);
	evutil_timerclear(&tv);
	tv.tv_sec = 1000;
	event_add(&ev, &tv);

	event_base_dispatch(base);

	for (i = 0; i < NUM_THREADS; ++i)
		THREAD_JOIN(threads[i]);

	event_del(&ev);

	tt_int_op(count, ==, NUM_THREADS * NUM_ITERATIONS);

	EVTHREAD_FREE_LOCK(count_lock, 0);
end:
	;
}

#undef NUM_THREADS
#define NUM_THREADS 10

struct alerted_record {
	struct cond_wait *cond;
	struct timeval delay;
	struct timeval alerted_at;
	int timed_out;
};

static THREAD_FN
wait_for_condition(void *arg)
{
	struct alerted_record *rec = arg;
	int r;

	EVLOCK_LOCK(rec->cond->lock, 0);
	if (rec->delay.tv_sec || rec->delay.tv_usec) {
		r = EVTHREAD_COND_WAIT_TIMED(rec->cond->cond, rec->cond->lock,
		    &rec->delay);
	} else {
		r = EVTHREAD_COND_WAIT(rec->cond->cond, rec->cond->lock);
	}
	EVLOCK_UNLOCK(rec->cond->lock, 0);

	evutil_gettimeofday(&rec->alerted_at, NULL);
	if (r == 1)
		rec->timed_out = 1;

	THREAD_RETURN();
}

static void
thread_conditions_simple(void *arg)
{
	struct timeval tv_signal, tv_timeout, tv_broadcast;
	struct alerted_record alerted[NUM_THREADS];
	THREAD_T threads[NUM_THREADS];
	struct cond_wait cond;
	int i;
	struct timeval launched_at;
	struct event wake_one;
	struct event wake_all;
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	int n_timed_out=0, n_signal=0, n_broadcast=0;

	tv_signal.tv_sec = tv_timeout.tv_sec = tv_broadcast.tv_sec = 0;
	tv_signal.tv_usec = 30*1000;
	tv_timeout.tv_usec = 150*1000;
	tv_broadcast.tv_usec = 500*1000;

	EVTHREAD_ALLOC_LOCK(cond.lock, EVTHREAD_LOCKTYPE_RECURSIVE);
	EVTHREAD_ALLOC_COND(cond.cond);
	tt_assert(cond.lock);
	tt_assert(cond.cond);
	for (i = 0; i < NUM_THREADS; ++i) {
		memset(&alerted[i], 0, sizeof(struct alerted_record));
		alerted[i].cond = &cond;
	}

	/* Threads 5 and 6 will be allowed to time out */
	memcpy(&alerted[5].delay, &tv_timeout, sizeof(tv_timeout));
	memcpy(&alerted[6].delay, &tv_timeout, sizeof(tv_timeout));

	evtimer_assign(&wake_one, base, wake_one_timeout, &cond);
	evtimer_assign(&wake_all, base, wake_all_timeout, &cond);

	evutil_gettimeofday(&launched_at, NULL);

	/* Launch the threads... */
	for (i = 0; i < NUM_THREADS; ++i) {
		THREAD_START(threads[i], wait_for_condition, &alerted[i]);
	}

	/* Start the timers... */
	tt_int_op(event_add(&wake_one, &tv_signal), ==, 0);
	tt_int_op(event_add(&wake_all, &tv_broadcast), ==, 0);

	/* And run for a bit... */
	event_base_dispatch(base);

	/* And wait till the threads are done. */
	for (i = 0; i < NUM_THREADS; ++i)
		THREAD_JOIN(threads[i]);

	/* Now, let's see what happened. At least one of 5 or 6 should
	 * have timed out. */
	n_timed_out = alerted[5].timed_out + alerted[6].timed_out;
	tt_int_op(n_timed_out, >=, 1);
	tt_int_op(n_timed_out, <=, 2);

	for (i = 0; i < NUM_THREADS; ++i) {
		const struct timeval *target_delay;
		struct timeval target_time, actual_delay;
		if (alerted[i].timed_out) {
			TT_BLATHER(("%d looks like a timeout\n", i));
			target_delay = &tv_timeout;
			tt_assert(i == 5 || i == 6);
		} else if (evutil_timerisset(&alerted[i].alerted_at)) {
			long diff1,diff2;
			evutil_timersub(&alerted[i].alerted_at,
			    &launched_at, &actual_delay);
			diff1 = timeval_msec_diff(&actual_delay,
			    &tv_signal);
			diff2 = timeval_msec_diff(&actual_delay,
			    &tv_broadcast);
			if (abs(diff1) < abs(diff2)) {
				TT_BLATHER(("%d looks like a signal\n", i));
				target_delay = &tv_signal;
				++n_signal;
			} else {
				TT_BLATHER(("%d looks like a broadcast\n", i));
				target_delay = &tv_broadcast;
				++n_broadcast;
			}
		} else {
			TT_FAIL(("Thread %d never got woken", i));
			continue;
		}
		evutil_timeradd(target_delay, &launched_at, &target_time);
		test_timeval_diff_leq(&target_time, &alerted[i].alerted_at,
		    0, 50);
	}
	tt_int_op(n_broadcast + n_signal + n_timed_out, ==, NUM_THREADS);
	tt_int_op(n_signal, ==, 1);

end:
	;
}

#define TEST(name)							\
	    { #name, thread_##name, TT_FORK|TT_NEED_THREADS|TT_NEED_BASE, \
	      &basic_setup, NULL }
struct testcase_t thread_testcases[] = {
	TEST(basic),
	TEST(conditions_simple),
	END_OF_TESTCASES
};

