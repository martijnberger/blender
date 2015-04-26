/*
 * Copyright 2011-2013 Blender Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __UTIL_THREAD_H__
#define __UTIL_THREAD_H__

#if (__cplusplus > 199711L) || (defined(_MSC_VER) && _MSC_VER >= 1800)
#  include <thread>
#  include <mutex>
#  include <condition_variable>
#  include <functional>
#else
#  include <boost/thread.hpp>
#endif
#include <pthread.h>
#include <queue>

#include "util_function.h"
#include "util_logging.h"

CCL_NAMESPACE_BEGIN

#if (__cplusplus > 199711L) || (defined(_MSC_VER) && _MSC_VER >= 1800)
typedef std::mutex thread_mutex;
typedef std::unique_lock<std::mutex> thread_scoped_lock;
typedef std::condition_variable thread_condition_variable;
#else
/* use boost for mutexes */
typedef boost::mutex thread_mutex;
typedef boost::mutex::scoped_lock thread_scoped_lock;
typedef boost::condition_variable thread_condition_variable;
#endif

/* own pthread based implementation, to avoid boost version conflicts with
 * dynamically loaded blender plugins */

class thread {
public:
	thread(function<void(void)> run_cb_)

	{
		joined = false;
		run_cb = run_cb_;

		pthread_create(&pthread_id, NULL, run, (void*)this);
	}

	~thread()
	{
		if(!joined)
			join();
	}

	static void *run(void *arg)
	{
		((thread*)arg)->run_cb();
		return NULL;
	}

	bool join()
	{
		joined = true;
		return pthread_join(pthread_id, NULL) == 0;
	}

protected:
	function<void(void)> run_cb;
	pthread_t pthread_id;
	bool joined;
};

template<typename T>
class ProducerConsumer
{
	thread_mutex queue_lock;
	thread_condition_variable queue_not_empty;
	thread_condition_variable queue_not_full;

	typedef std::deque<T> Queue;
	Queue queue;

public:
	typedef typename Queue::size_type size_type;
	typedef typename Queue::difference_type difference_type;

private:
	size_type max_items;

	/* disable copy construct and assignment */
	ProducerConsumer(const ProducerConsumer&);	/* = delete; */
	void operator=(const ProducerConsumer&);	/* = delete; */

public:
	ProducerConsumer()
		: max_items(queue.max_size())
	{
	}

	void set_limit(size_type limit)
	{
		thread_scoped_lock lock(queue_lock);

		assert(limit > 0);

		bool was_full = (queue.size() == max_items);

		/* clamp limit to valid range */
		if (limit == max_items)
			return;
		if (limit < 1)
			limit = 1;
		else if (limit > queue.max_size())
			limit = queue.max_size();

		int notify;

		/* need to have two code paths to avoid signed overflow */
		if (limit > max_items) {
			size_type added_space = limit - max_items;
			max_items = limit;
			notify = !was_full ? 0 : added_space > 1 ? 2 : 1;
		}
		else {
			max_items = limit;
			notify = 0;
		}

		if (notify > 1)
			queue_not_full.notify_all();
		else if (notify > 0)
			queue_not_full.notify_one();
	}

	void push(const T& item)
	{
		thread_scoped_lock lock(queue_lock);

		/* wait for queue to not be full */
		while (queue.size() == max_items)
			queue_not_full.wait(lock);

		queue.push_back(item);

		/* if queue was empty before, notify one consumer */
		if (queue.size() == 1)
			queue_not_empty.notify_one();
	}

	void pop(T& item)
	{
		thread_scoped_lock lock(queue_lock);

		/* wait for queue to not be empty */
		DLOG(INFO) << "Waiting for pop";
		while (queue.empty())
			queue_not_empty.wait(lock);

		item = queue.front();
		queue.pop_front();

		/* if queue was full before, notify one producer */
		if (queue.size() == max_items - 1)
			queue_not_full.notify_one();
	}

	template<typename I>
	void push_range(const I& begin, const I& end)
	{
		thread_scoped_lock lock(queue_lock);

		bool was_empty = queue.empty();

		for (I iter = begin; iter != end; ++iter) {
			/* wait for queue to not be full */
			while (queue.size() == max_items)
				queue_not_empty.wait(lock);

			queue.push_back(*iter);
		}

		if (was_empty) {
			if (queue.size() > 1)
				queue_not_empty.notify_all();
			else
				queue_not_empty.notify_one();
		}
	}

	/* atomically puts entire queue content into the passed container
	 * (which requires push_back).
	 * if wait parameter is true, wait for at least one item */
	template<typename C>
	bool pop_all_into(C &output_container, bool wait)
	{
		thread_scoped_lock lock(queue_lock);

		if (!wait && queue.empty())
			return false;

		/* wait for queue to not be empty */
		while (queue.empty())
			queue_not_empty.wait(lock);

		std::copy(queue.begin(), queue.end(), std::back_inserter(output_container));

		bool was_full = (queue.size() == max_items);

		queue.clear();

		/* if queue was full before, notify all producers */
		if (was_full) {
			if (max_items > 1)
				queue_not_full.notify_all();
			else
				queue_not_full.notify_one();
		}
	}

	/* when we have C++11 use perfect forwarding */
	template<typename C>
	void push_all_from(const C &input_container)
	{
		push_range(input_container.begin(), input_container.end());
	}

	bool try_push(const T& item)
	{
		thread_scoped_lock lock(queue_lock);

		if (queue.size() == max_items)
			return false;

		queue.push_back(item);

		/* if queue was empty before, notify one consumer */
		if (queue.size() == 1)
			queue_not_empty.notify_one();

		return true;
	}

	bool try_pop(T& item)
	{
		thread_scoped_lock lock(queue_lock);

		if (queue.empty())
			return false;

		item = queue.front();
		queue.pop_front();

		/* if queue was full before, notify one producer */
		if (queue.size() == max_items - 1)
			queue_not_full.notify_one();

		return true;
	}

	bool empty() const
	{
		thread_scoped_lock lock(queue_lock);
		return queue.empty();
	}

	size_type size() const
	{
		thread_scoped_lock lock(queue_lock);
		return queue.size();
	}

	size_type capacity() const
	{
		return max_items;
	}

	void clear()
	{
		thread_scoped_lock lock(queue_lock);

		/* use swap instead of clear so it will
		 * actually deallocate memory */
		std::swap(queue, Queue());

		/* empty queue is not full by definition */
		queue_not_full.notify_all();
	}
};

CCL_NAMESPACE_END

#endif /* __UTIL_THREAD_H__ */

