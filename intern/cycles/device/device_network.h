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

#ifndef __DEVICE_NETWORK_H__
#define __DEVICE_NETWORK_H__

#if defined(WITH_NETWORK)

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/thread.hpp>
#include <boost/static_assert.hpp>

#include <iostream>
#include <sstream>
#include <deque>
#include <limits>

/* need strictly sized types for serializer */
#include <stdint.h>

/* some platforms have their endian swap implementation here */
#include <stdlib.h>

#include "buffers.h"

#include "util_foreach.h"
#include "util_list.h"
#include "util_logging.h"
#include "util_map.h"
#include "util_string.h"

CCL_NAMESPACE_BEGIN

using std::cout;
using std::cerr;
using std::hex;
using std::setw;
using std::exception;

using boost::asio::ip::tcp;

static const int SERVER_PORT = 5120;
static const int DISCOVER_PORT = 5121;
static const string DISCOVER_REQUEST_MSG = "REQUEST_RENDER_SERVER_IP";
static const string DISCOVER_REPLY_MSG = "REPLY_RENDER_SERVER_IP";

/* RAM copy of device memory on server side. On some devices, this is the
 * actual data storage and the device doesn't have a copy, it uses it directly */

typedef vector<char> ByteVector;

class network_device_memory : public device_memory
{
public:
	network_device_memory() {}
	~network_device_memory() { device_pointer = 0; }

	ByteVector local_data;
};

/* RPC protocol:
 * Each outgoing packet could be a call or it could be a response from a call.
 * Stream format for a packet:
 *
 *  <header size=8>
 *  <parameters size=header::len>
 *  <blob size=header::blob_len>
 *
 *  RPCHeader structure: tag, id, length, signature
 *   tag: a unique identifier used to match up requests and responses. The
 *   response will have the same tag as the request.
 *   id: an number that identifies which call is being done. Calls and responses
 *   have different IDs.
 *   length: the length of the following serialized call parameters data
 *   signature: always 0xBB
 *   blob_len: 32-bit length of blob payload after serialized parameters
 *  serialized parameters (length = RPCHeader::length) (optional):
 *   The RPCCallBase class defines the layout of these serialized values
 *  blob (length = RPCHeader::blob_len) (optional):
 *
 */

/* verify that the current architecture has IEEE754 floating point format
 * IEC559 and IEEE754 mean the same thing */
BOOST_STATIC_ASSERT(std::numeric_limits<float>::is_iec559);
BOOST_STATIC_ASSERT(std::numeric_limits<double>::is_iec559);

/* template which compiles to a no-op on little endian platform */
template<bool need_swap>
struct EndianSwap
{
	static void swap64(char *data) {}
	static void swap32(char *data) {}
	static void swap16(char *data) {}
	static void swap8(char *data) {}
};

/* byte swapper that works on any platform.
 * C++ standard guarantees that aliasing works properly through char pointer. */
template<>
struct EndianSwap<true>
{
	static void swap64(char *data)
	{
		std::swap(data[0], data[7]);
		std::swap(data[1], data[6]);
		std::swap(data[2], data[5]);
		std::swap(data[3], data[4]);
	}
	static void swap32(char *data)
	{
		std::swap(data[0], data[3]);
		std::swap(data[1], data[2]);
	}
	static void swap16(char *data)
	{
		std::swap(data[0], data[1]);
	}
	static void swap8(char *data)
	{
	}
};

class Endian
{

#ifdef __LITTLE_ENDIAN__
	typedef EndianSwap<false> Swapper;
#else
	typedef EndianSwap<true> Swapper;
#endif

public:
	/* specialize to compiler intrinsics for efficient byteswap on supported compilers */
#if defined(__GNUC__)
	static inline uint64_t swap(uint64_t x) { return __builtin_bswap64(x); }
	static inline uint64_t swap(int64_t x)  { return __builtin_bswap64((uint64_t)x); }
	static inline uint32_t swap(uint32_t x) { return __builtin_bswap32(x); }
	static inline uint32_t swap(int32_t x)  { return __builtin_bswap32((uint32_t)x); }
	static inline uint16_t swap(uint16_t x) { return __builtin_bswap16(x); }
	static inline uint16_t swap(int16_t x)  { return __builtin_bswap16((uint16_t)x); }
	static inline uint8_t swap(uint8_t x)   { return x; }
	static inline uint8_t swap(int8_t x)    { return (uint8_t)x; }
#elif defined(_MSC_VER)
	static inline uint64_t swap(uint64_t x) { return _byteswap_uint64(x); }
	static inline uint64_t swap(int64_t x)  { return _byteswap_uint64((uint64_t)x); }
	static inline uint32_t swap(uint32_t x) { return _byteswap_ulong(x); }
	static inline uint32_t swap(int32_t x)  { return _byteswap_ulong((uint32_t)x); }
	static inline uint16_t swap(uint16_t x) { return _byteswap_ushort(x); }
	static inline uint16_t swap(int16_t x)  { return _byteswap_ushort((uint16_t)x); }
	static inline uint8_t swap(uint8_t x)   { return x; }
	static inline uint8_t swap(int8_t x)    { return (uint8_t)x; }
#else
	static inline uint64_t swap(uint64_t x) { Swapper::swap64((char*)&x); return x; }
	static inline uint64_t swap(int64_t x)  { Swapper::swap64((char*)&x); return x; }
	static inline uint32_t swap(uint32_t x) { Swapper::swap32((char*)&x); return x; }
	static inline uint32_t swap(int32_t x)  { Swapper::swap32((char*)&x); return x; }
	static inline uint16_t swap(uint16_t x) { Swapper::swap16((char*)&x); return x; }
	static inline uint16_t swap(int16_t x)  { Swapper::swap16((char*)&x); return x; }
	static inline uint8_t swap(uint8_t x)   { return x; }
	static inline uint8_t swap(int8_t x)    { return (uint8_t)x; }
#endif

	/* all compilers are stupid about endian conversions with floating point types */
	static inline uint32_t swap(float x)
	{
		uint32_t nonfloat;
		memcpy(&nonfloat, &x, sizeof(nonfloat));
		return swap(nonfloat);
	}
	static inline uint64_t swap(double x)
	{
		uint64_t nonfloat;
		memcpy(&nonfloat, &x, sizeof(nonfloat));
		return swap(nonfloat);
	}
};

/* helper needed because we don't use c++11.
 * when we have c++11 we should use 'typename std::make_unsigned<T>::type' */
template<typename T> struct ToUnsigned { typedef T type; };
template<> struct ToUnsigned<int64_t>  { typedef uint64_t type; };
template<> struct ToUnsigned<int32_t>  { typedef uint32_t type; };
template<> struct ToUnsigned<int16_t>  { typedef uint16_t type; };
template<> struct ToUnsigned<int8_t>   { typedef uint8_t type; };
template<> struct ToUnsigned<float>    { typedef uint32_t type; };
template<> struct ToUnsigned<double>   { typedef uint64_t type; };

/* each RPC call has this fixed-size header for variable sized data that follows */
struct RPCHeader
{
	/* each request gets an unused tag value.
	 * the response will have the same tag as the request */
	uint8_t tag;

	/* the id identifies the type of the packet.
	 * requests and responses have different identifiers */
	uint8_t id;

	/* size in bytes of the following payload (not including this header) */
	uint8_t length;

	/* signature to ensure synchronization */
	uint8_t signature;

	/* length of blob, which comes after serialized parameters */
	uint32_t blob_len;
};

template<size_t buffer_max>
class RPCCallBase
{
protected:
	void *blob_ptr;
	size_t blob_size;

	uint8_t call_id;

	/* for performance, a statically allocated buffer is used */
	uint8_t buffer[buffer_max];
	uint8_t add_point;
	uint8_t read_point;

	/* masks for type size prefixes */
	enum SizeFlags {
		size_mask = 0x0F,
		is_unsigned = 0x10,
		is_float = 0x20,
		is_string = 0x40,
		is_zero = 0x80
	};

	inline RPCCallBase(uint8_t call_id)
		: blob_ptr(NULL)
		, blob_size(0)
		, call_id(call_id)
		, add_point(0)
		, read_point(0)
	{
	}

	template<typename Tcheck, typename Tactual>
	static inline bool in_range(Tactual a)
	{
		return a >= (std::numeric_limits<Tcheck>::min)()
				&& a <= (std::numeric_limits<Tcheck>::max)();
	}

	void add_blob(void *mem, size_t size)
	{
		assert(blob_ptr == NULL);
		assert(blob_size == 0);
		blob_ptr = mem;
		blob_size = size;
	}

	void add(const std::string& str)
	{
		assert(str.length() < 256);
		assert(add_point + 1 + 1 + str.length() <= buffer_max);
		buffer[add_point++] = is_string;
		buffer[add_point++] = (uint8_t)str.length();
		memcpy(buffer + add_point, str.c_str(), str.length());
		add_point += str.length();
	}

	/* used to serialize a new item into buffer[] */
	template<typename T>
	void add(T a)
	{
		typename ToUnsigned<T>::type little_endian_a = Endian::swap(a);

		/* make sure there's enough room for a type prefix */
		assert(add_point + 1 <= buffer_max);

		uint8_t type_size = 0;

		if (!std::numeric_limits<T>::is_integer) {
			/* floating point type */
			if (memcmp(&a, "\0\0\0\0\0\0\0\0", sizeof(a)) == 0)
				type_size = 0 | is_zero;
			else if (sizeof(a) == 4)
				type_size = 4 | is_float;
			else
				assert(!"This shouldn't be possible");
		}
		else if (std::numeric_limits<T>::is_signed) {
			/* signed type */
			if (a == 0)
				type_size = 0 | is_zero;
			else if (in_range<int8_t,T>(a))
				type_size = 1;
			else if (in_range<int16_t,T>(a))
				type_size = 2;
			else if (in_range<int32_t,T>(a))
				type_size = 4;
			else if (in_range<int64_t,T>(a))
				type_size = 8;
			else
				assert(!"This shouldn't be possible");
		}
		else {
			/* unsigned type */
			if (a == 0)
				type_size = 0 | is_zero;
			else if (in_range<uint8_t,T>(a))
				type_size = 1 | is_unsigned;
			else if (in_range<uint16_t,T>(a))
				type_size = 2 | is_unsigned;
			else if (in_range<uint32_t,T>(a))
				type_size = 4 | is_unsigned;
			else if (in_range<uint64_t,T>(a))
				type_size = 8 | is_unsigned;
			else
				assert(!"This shouldn't be possible");
		}

		/* make sure there's enough room for a type prefix and data */
		assert(add_point + 1 + (type_size & size_mask) <= buffer_max);

		/* size of type, followed by data */
		buffer[add_point++] = type_size;
		if ((type_size & is_zero) == 0) {
			memcpy(buffer + add_point, &little_endian_a, type_size & size_mask);
			add_point += type_size & size_mask;
		}
	}

	/* overload to avoid problem with shifting float
	 * no code path will call this, it is to make compiler happy */
	static inline float sign_extend(float a, unsigned)
	{
		return a;
	}

	/* sign extend integer type */
	template<typename T>
	static inline T sign_extend(T a, unsigned size)
	{
		int shift = 32 - (size * 8);
		a <<= shift;
		a >>= shift;
		return a;
	}

	/* used to deserialize an item from buffer[] */
	template<typename T>
	void read(T &result)
	{
		/* make sure we can read type_size
		 * and make sure we can read type length bytes */
		assert(read_point < buffer_max);

		/* get type prefix */
		uint8_t type_size = buffer[read_point];

		/* extract compressed data length */
		unsigned size_bytes = type_size & size_mask;

		/* make sure we can read the specified size */
		assert(read_point + size_bytes < buffer_max);

		/* it's only safe to memset for POD types!
		 * When we can use c++11 we can make sure at compile time */
		memset(&result, 0, sizeof(result));

		typename ToUnsigned<T>::type little_endian_value;

		memcpy(&little_endian_value, buffer + read_point + 1, size_bytes);

		/* sign extend */
		if ((type_size & (is_unsigned|is_zero|is_float)) == 0
				&& (type_size & size_mask) != sizeof(result)) {
			little_endian_value = sign_extend(little_endian_value, size_bytes);
		}

		typename ToUnsigned<T>::type native_endian_value;
		native_endian_value = Endian::swap(little_endian_value);

		/* at this point, any_endian_value is the native endianness */
		memcpy(&result, &native_endian_value, sizeof(result));

		read_point += 1 + size_bytes;
	}

	void read(string& result)
	{
		assert(read_point + 1 < buffer_max);
		uint8_t type_len = buffer[read_point++];
		assert((type_len & is_string) != 0);

		uint8_t str_len = buffer[read_point++];
		assert(str_len < 256);

		result.assign(buffer + read_point, buffer + read_point + str_len);

		read_point += str_len;
	}

public:
	typedef std::pair<void*,uint32_t> ResponseInfo;

	/* returns true if there is a response */
	virtual bool send_request() = 0;

	/* receives the response payload this request */
	virtual ResponseInfo response_info()
	{
		return ResponseInfo(NULL, 0);
	}
};

/* cycles-specifics are in here */
class CyclesRPCCallBase : public RPCCallBase<256>
{
public:
	static const size_t max_payload = 256;

private:
	typedef RPCCallBase<256> Base;

public:
	/* uniquely identifies a call, responses will have a matching tag */
	typedef uint8_t CallTag;

	/* pointer to, and length of, the serialized parameters */
	typedef std::pair<const void *,size_t> ParameterBuffer;

	enum CallID
	{
		invalid_call,

		/* requests */
		mem_alloc_request,
		stop_request,
		mem_mem_copy_to_request,
		mem_copy_from_request,
		mem_zero_request,
		mem_free_request,
		const_copy_to_request,
		tex_alloc_request,
		tex_free_request,
		load_kernels_request,
		task_add_request,
		task_wait_request,
		task_cancel_request,
		acquire_tile_request,
		release_tile_request,
		task_wait_done_request,
		task_acquire_tile_request,
		task_release_tile_request,

		/* responses */
		response_flag = 0x80,
		mem_alloc_response,
		acquire_tile_response,
		release_tile_response,

		last_CallID
	};

	const char* get_call_id_name()
	{
		switch(call_id){
		case invalid_call: return "invalid_call";
		case mem_alloc_request: return "mem_alloc_request";
		case stop_request: return "stop_request";
		case mem_mem_copy_to_request: return "mem_mem_copy_to_request";
		case mem_copy_from_request: return "mem_copy_from_request";
		case mem_zero_request: return "mem_zero_request";
		case mem_free_request: return "mem_free_request";
		case const_copy_to_request: return "const_copy_to_request";
		case tex_alloc_request: return "tex_alloc_request";
		case tex_free_request: return "tex_free_request";
		case load_kernels_request: return "load_kernels_request";
		case task_add_request: return "task_add_request";
		case task_wait_request: return "task_wait_request";
		case task_cancel_request: return "task_cancel_request";
		case acquire_tile_request: return "acquire_tile_request";
		case release_tile_request: return "release_tile_request";
		case task_wait_done_request: return "task_wait_done_request";
		case task_acquire_tile_request: return "task_acquire_tile_request";
		case task_release_tile_request: return "task_release_tile_request";

		/* responses */
		case mem_alloc_response: return "mem_alloc_response";
		case acquire_tile_response: return "acquire_tile_response";
		case release_tile_response: return "release_tile_response";
		default: return "Unkown call";
		}
	}

	CallID get_call_id() const
	{
		return (CallID)call_id;
	}

	RPCHeader make_call_header() const
	{
		RPCHeader header;
		header.tag = call_tag;
		header.id = call_id;
		header.length = add_point;
		header.signature = 0xBB;
		return header;
	}

	ParameterBuffer get_parameters() const
	{
		return ParameterBuffer(buffer, add_point);
	}

	ParameterBuffer get_blob() const
	{
		return ParameterBuffer(blob_ptr, blob_size);
	}

protected:
	CallTag call_tag;

	 CyclesRPCCallBase(CallID call_id)
		: RPCCallBase(call_id)
	{
	}

public:
	/* serialize a device_memory */
	void add(const device_memory& mem)
	{
		int type = (int)mem.data_type;
		Base::add(type);
		Base::add(mem.data_elements);
		Base::add(mem.data_size);
		Base::add(mem.data_width);
		Base::add(mem.data_height);
		Base::add(mem.device_pointer);
	}

	/* deserialize a device_memory */
	void read(device_memory& mem)
	{
		int type;
		Base::read(type);
		Base::read(mem.data_elements);
		Base::read(mem.data_size);
		Base::read(mem.data_width);
		Base::read(mem.data_height);
		Base::read(mem.device_pointer);
		mem.data_type = (DataType)type;
	}

	/* serialize a DeviceTask */
	void add(const DeviceTask& task)
	{
		int type = (int)task.type;
		Base::add(type);
		Base::add(task.x);
		Base::add(task.y);
		Base::add(task.w);
		Base::add(task.h);
		Base::add(task.rgba_byte);
		Base::add(task.rgba_half);
		Base::add(task.buffer);
		Base::add(task.sample);
		Base::add(task.num_samples);
		Base::add(task.offset);
		Base::add(task.stride);
		Base::add(task.shader_input);
		Base::add(task.shader_output);
		Base::add(task.shader_eval_type);
		Base::add(task.shader_x);
		Base::add(task.shader_w);
		Base::add(task.need_finish_queue);
	}

	/* deserialize a DeviceTask */
	void read(DeviceTask& task)
	{
		int type;
		Base::read(type);
		Base::read(task.x);
		Base::read(task.y);
		Base::read(task.w);
		Base::read(task.h);
		Base::read(task.rgba_byte);
		Base::read(task.rgba_half);
		Base::read(task.buffer);
		Base::read(task.sample);
		Base::read(task.num_samples);
		Base::read(task.offset);
		Base::read(task.stride);
		Base::read(task.shader_input);
		Base::read(task.shader_output);
		Base::read(task.shader_eval_type);
		Base::read(task.shader_x);
		Base::read(task.shader_w);
		Base::read(task.need_finish_queue);
		task.type = (DeviceTask::Type)type;
	}

	/* serialize a RenderTile */
	void add(const RenderTile& tile)
	{
		Base::add(tile.x);
		Base::add(tile.y);
		Base::add(tile.w);
		Base::add(tile.h);
		Base::add(tile.start_sample);
		Base::add(tile.num_samples);
		Base::add(tile.sample);
		Base::add(tile.resolution);
		Base::add(tile.offset);
		Base::add(tile.stride);
		Base::add(tile.buffer);
		Base::add(tile.rng_state);
	}

	/* serialize a RenderTile */
	void read(RenderTile& tile)
	{
		Base::read(tile.x);
		Base::read(tile.y);
		Base::read(tile.w);
		Base::read(tile.h);
		Base::read(tile.start_sample);
		Base::read(tile.num_samples);
		Base::read(tile.sample);
		Base::read(tile.resolution);
		Base::read(tile.offset);
		Base::read(tile.stride);
		Base::read(tile.buffer);
		Base::read(tile.rng_state);
	}

	template<typename T>
	void add(const T &a)
	{
		Base::add(a);
	}

	template<typename T>
	void read(T &a)
	{
		Base::read(a);
	}

};

/* implement a pointer that knows when to delete its object on destruct */
template<typename T>
class OwnershipPointer
{
	T *item;
	bool own;

	OwnershipPointer(const OwnershipPointer&);
	void operator=(const OwnershipPointer&);

public:
	OwnershipPointer()
		: item(NULL), own(false)
	{
	}

	OwnershipPointer(T *item, bool owned)
		: item(item), own(owned)
	{
	}

	~OwnershipPointer()
	{
		if (own)
			delete item;
	}

	void assign(T *assigned_item, bool take_ownership)
	{
		if (own)
			delete item;
		item = assigned_item;
		own = take_ownership;
	}

	T &operator*() { return *item; }
	const T &operator*() const { return *item; }
	T *operator->() { return item; }
	const T *operator->() const { return item; }
	operator T*() { return item; }
	operator const T*() const { return item; }
};

class RPCCall_mem_alloc : public CyclesRPCCallBase
{
public:
	OwnershipPointer<device_memory> mem;
	MemoryType type;

private:
	bool send_request()
	{
		int inttype = (int)type;
		add(*mem);
		add(inttype);
		return false;
	}

public:
	RPCCall_mem_alloc(device_memory& mem, MemoryType type)
		: CyclesRPCCallBase(mem_alloc_request)
		, mem(&mem, false), type(type)
	{}

	RPCCall_mem_alloc(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
		int inttype;
		mem.assign(new network_device_memory, true);
		read(*mem);
		read(inttype);
		type = (MemoryType)inttype;
	}
};

class RPCCall_stop : public CyclesRPCCallBase
{
	bool send_request()
	{
		return false;
	}

public:
	RPCCall_stop()
		: CyclesRPCCallBase(stop_request)
	{}

	RPCCall_stop(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_mem_copy_to : public CyclesRPCCallBase
{
private:
	OwnershipPointer<device_memory> mem;

	bool send_request()
	{
		add(*mem);
		add_blob((void*)mem->data_pointer, mem->memory_size());
		return false;
	}

public:
	RPCCall_mem_copy_to(device_memory& mem)
		: CyclesRPCCallBase(mem_mem_copy_to_request)
		, mem(&mem, false)
	{}

	RPCCall_mem_copy_to(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_mem_copy_from : public CyclesRPCCallBase
{
	OwnershipPointer<device_memory> mem;
	int y, w, h, elem;
	void *output;

	bool send_request()
	{
		add(*mem);
		add(y);
		add(w);
		add(h);
		add(elem);
		return true;
	}

	ResponseInfo response_info()
	{
		return ResponseInfo(output, mem->memory_size());
	}

public:
	RPCCall_mem_copy_from(device_memory& mem,
		int y, int w, int h, int elem, void *output)
		: CyclesRPCCallBase(mem_copy_from_request)
		, mem(&mem, false), y(y), w(w), h(h), elem(elem), output(output)
	{}

	RPCCall_mem_copy_from(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_mem_zero : public CyclesRPCCallBase
{
	OwnershipPointer<device_memory> mem;

	bool send_request()
	{
		add(*mem);
		return false;
	}

public:
	RPCCall_mem_zero(device_memory& mem)
		: CyclesRPCCallBase(mem_zero_request)
		, mem(&mem, false)
	{}

	RPCCall_mem_zero(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_mem_free : public CyclesRPCCallBase
{
	OwnershipPointer<device_memory> mem;

	bool send_request()
	{
		add(*mem);
		return false;
	}

public:
	RPCCall_mem_free(device_memory& mem)
		: CyclesRPCCallBase(mem_free_request)
		, mem(&mem, false)
	{}

	RPCCall_mem_free(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_const_copy_to : public CyclesRPCCallBase
{
	OwnershipPointer<const std::string> name;
	void *data;
	size_t size;

	bool send_request()
	{
		add(*name);
		add(size);
		add_blob(data, size);
		return false;
	}

public:
	RPCCall_const_copy_to(const std::string& name, void *data, size_t size)
		: CyclesRPCCallBase(const_copy_to_request)
		, name(&name, false), data(data), size(size)
	{}

	RPCCall_const_copy_to(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_tex_alloc : public CyclesRPCCallBase
{
	OwnershipPointer<const std::string> name;
	OwnershipPointer<device_memory> mem;
	bool interpolation, periodic;

	bool send_request()
	{
		add(*name);
		add(*mem);
		add(interpolation);
		add(periodic);
		/* FIXME: why are we sending this? */
		add_blob((void*)mem->device_pointer, mem->memory_size());
		return false;
	}

public:
	RPCCall_tex_alloc(const std::string& name,
		device_memory& mem, bool interpolation, bool periodic)
		: CyclesRPCCallBase(tex_alloc_request)
		, name(&name, false), mem(&mem, false)
		, interpolation(interpolation), periodic(periodic)
	{}

	RPCCall_tex_alloc(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_tex_free : public CyclesRPCCallBase
{
	OwnershipPointer<device_memory> mem;

	bool send_request()
	{
		add(*mem);
		return false;
	}

public:
	RPCCall_tex_free(device_memory& mem)
		: CyclesRPCCallBase(tex_free_request)
		, mem(&mem, false)
	{}

	RPCCall_tex_free(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_load_kernels : public CyclesRPCCallBase
{
	bool experimental;
	bool result;

	bool send_request()
	{
		add(experimental);
		return true;
	}

	ResponseInfo response_info()
	{
		return ResponseInfo(&result, 1);
	}

public:
	RPCCall_load_kernels(bool experimental)
		: CyclesRPCCallBase(CyclesRPCCallBase::load_kernels_request)
		, experimental(experimental)
	{
	}

	RPCCall_load_kernels(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}

	bool get_result() const
	{
		return result;
	}
};

class RPCCall_task_add : public CyclesRPCCallBase
{
	OwnershipPointer<DeviceTask> task;

	bool send_request()
	{
		add(*task);
		return false;
	}

public:
	RPCCall_task_add(DeviceTask& task)
		: CyclesRPCCallBase(task_add_request)
		, task(&task, false)
	{}

	RPCCall_task_add(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_task_wait : public CyclesRPCCallBase
{
	bool send_request()
	{
		return false;
	}

public:
	RPCCall_task_wait()
		: CyclesRPCCallBase(task_wait_request)
	{}

	RPCCall_task_wait(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_task_cancel : public CyclesRPCCallBase
{
	bool send_request()
	{
		return false; // false == fire and forget
	}

public:
	RPCCall_task_cancel()
		: CyclesRPCCallBase(task_cancel_request)
	{}

	RPCCall_task_cancel(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_acquire_tile : public CyclesRPCCallBase
{
	bool send_request()
	{
		return false;
	}

public:
	RPCCall_acquire_tile()
		: CyclesRPCCallBase(task_acquire_tile_request)
	{
	}

	RPCCall_acquire_tile(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_release_tile : public CyclesRPCCallBase
{
	bool send_request()
	{
		return false;
	}

public:
	RPCCall_release_tile()
		: CyclesRPCCallBase(task_release_tile_request)
	{
	}

	RPCCall_release_tile(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_task_wait_done : public CyclesRPCCallBase
{
	bool send_request()
	{
		return false;
	}

public:
	RPCCall_task_wait_done()
		: CyclesRPCCallBase(task_wait_done_request)
	{
	}

	RPCCall_task_wait_done(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_mem_alloc_response : public CyclesRPCCallBase
{
	bool send_request()
	{
		return false;
	}

public:
	RPCCall_mem_alloc_response()
		: CyclesRPCCallBase(mem_alloc_response)
	{
	}

	RPCCall_mem_alloc_response(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_acquire_tile_response : public CyclesRPCCallBase
{
	bool send_request()
	{
		return false;
	}

public:
	RPCCall_acquire_tile_response()
		: CyclesRPCCallBase(acquire_tile_response)
	{
	}

	RPCCall_acquire_tile_response(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

class RPCCall_release_tile_response : public CyclesRPCCallBase
{
	bool send_request()
	{
		return false;
	}

public:
	RPCCall_release_tile_response()
		: CyclesRPCCallBase(release_tile_response)
	{
	}

	RPCCall_release_tile_response(RPCHeader &header,
			ByteVector& args_buffer, ByteVector& blob_buffer)
		: CyclesRPCCallBase(CyclesRPCCallBase::CallID(header.id))
	{
	}
};

/* implements a generic thread-safe pool. Objects are guaranteed not to be moved.
 * pooled objects must be copy-constructible and default constructible.
 * they will only be copied when first created (until we can use c++11).
 * the specified initialization method will be called on creation (after it is
 * copied.) */
template<typename T, void (T::*init_method)()>
class LockedPool
{
	thread_mutex pool_lock;

	/* using deque so growing it won't cause any of the items to move
	 * to another address, maximize data locality, and allocate space
	 * for many objects per allocation */
	typedef std::deque<T> PoolStorage;
	PoolStorage pool_storage;

	/* pointers to unused items are stored in here */
	typedef std::vector<T*> PoolFreeList;
	PoolFreeList pool_free_list;

public:

	T *alloc_item()
	{
		T *result;
		thread_scoped_lock lock(pool_lock);
		if (!pool_free_list.empty()) {
			/* use item in free list */
			result = pool_free_list.back();
			pool_free_list.pop_back();
		}
		else {
			/* need to create a new item
			 * when we have c++11, use emplace_back here */
			pool_storage.push_back(T());
			result = &pool_storage.back();
			(result->*init_method)();
		}
		return result;
	}

	void free_item(T *waiter)
	{
		thread_scoped_lock lock(pool_lock);
		pool_free_list.push_back(waiter);
	}
};

class RPCStreamManager;

class CyclesRPCCallFactory
{
public:
	static CyclesRPCCallBase *decode_item(RPCHeader &header,
			ByteVector &args_buffer,
			ByteVector &blob_buffer);

	static void rpc_mem_alloc(RPCStreamManager& stream,
			device_memory& mem, MemoryType type);

	static void rpc_stop(RPCStreamManager& stream);

	static void rpc_mem_copy_to(RPCStreamManager& stream, device_memory& mem);

	static void rpc_mem_copy_from(RPCStreamManager& stream,
			device_memory& mem, int y, int w, int h, int elem, void *output);

	static void rpc_mem_zero(RPCStreamManager& stream,
			device_memory& mem);

	static void rpc_mem_free(RPCStreamManager& stream,
			device_memory& mem);

	static void rpc_const_copy_to(RPCStreamManager& stream,
			const std::string& name, void *data, size_t size);

	static void rpc_tex_alloc(RPCStreamManager& stream,
			const std::string& name, device_memory& mem,
			bool interpolation, bool periodic);

	static void rpc_tex_free(RPCStreamManager& stream,
			device_memory& mem);

	static bool rpc_load_kernels(RPCStreamManager& stream,
			bool experimental);

	static void rpc_task_add(RPCStreamManager& stream,
			DeviceTask& task);

	static void rpc_task_wait(RPCStreamManager& stream);

	static void rpc_task_cancel(RPCStreamManager& stream);

	static void rpc_acquire_tile_response(RPCStreamManager& stream, CyclesRPCCallBase *request,
			bool retval, RenderTile& tile);

	static void rpc_release_tile(RPCStreamManager& stream, RenderTile& tile);
};

/* RPC stream manager
 *  on the server side:
 *   - it provides a way for the main thread to wait for and return
 *	   incoming RPC requests, and later send back responses for those
 *     requests.
 *   - it provides a way for arbitrary server threads to make calls
 *     back to the client. If the call returns data, it blocks until
 *     the response is received, receives the response, and returns
 *     the result
 *  on the client side:
 *   - it provides a way for the main thread to send calls to the
 *     server. If the call returns data, it blocks until the response
 *     is received, receives the response, and returns the result
 *   - it receives calls from the server, invokes them, and if they
 *     return a result, sends the response
 */
class RPCStreamManager
{
	//boost::asio::io_service io_service;
	boost::asio::ip::tcp::socket& socket;

	/* there can be contention to send, because sends can be performed from any thread
	 * there can't be contention to receive, we always have async receives up, and
	 * receives are continuously services by the io_service thread */
	thread_mutex send_lock;

	/* receive stream management data */

	enum ReceiveState
	{
		receiving_header,
		receiving_args,
		receiving_blob,
		receive_aborted
	};

	ReceiveState recv_state;

	RPCHeader recv_header;
	ByteVector recv_args_buffer;
	ByteVector recv_blob_buffer;

	/* object upon which to block when waiting */
	class Waiter
	{
		/* mutex can't be copied, so use a pointer and enforce
		 * that this object is never copied after it is created */
		thread_mutex *done_lock;
		thread_condition_variable *done_cond;

		CyclesRPCCallBase::CallID call_id;
		bool done;

		void assert_uninitalized()
		{
			assert(done_lock == NULL);
			assert(done_cond == NULL);
		}

		void assert_initalized()
		{
			assert(done_lock != NULL);
			assert(done_cond != NULL);
		}

	public:
		Waiter()
			: done_lock(NULL)
			, done_cond(NULL)
			, call_id(CyclesRPCCallBase::invalid_call)
			, done(false)
		{
		}

		Waiter(CyclesRPCCallBase::CallID call_id)
			: done_lock(NULL)
			, done_cond(NULL)
			, call_id(call_id)
			, done(false)
		{
		}

		Waiter(const Waiter& rhs)
		{
			assert_uninitalized();
			call_id = rhs.call_id;
			done = rhs.done;
		}

		~Waiter()
		{
			delete done_lock;
			delete done_cond;
		}

		void init()
		{
			assert_uninitalized();
			done_lock = new thread_mutex;
			done_cond = new thread_condition_variable;
		}

		void wait()
		{
			assert_initalized();
			thread_scoped_lock lock(*done_lock);
			while (!done)
				done_cond->wait(lock);
		}

		void notify()
		{
			assert_initalized();
			thread_scoped_lock lock(*done_lock);
			done = true;
			done_cond->notify_one();
		}
	};

	/* we don't want to be constantly creating and destroying
	 * mutices and condition variables, so pool them */
	typedef LockedPool<Waiter,&Waiter::init> WaiterPool;
	WaiterPool waiter_pool;

	thread_mutex waiter_map_lock;
	typedef std::map<uint8_t,Waiter*> WaiterMap;
	WaiterMap waiter_map;

	/* queue for incoming packets that aren't responses */
	ProducerConsumer<CyclesRPCCallBase*> recv_queue;

	/* send implementation */

	Waiter *register_for_unblock(CyclesRPCCallBase::CallTag tag)
	{
		Waiter *waiter = waiter_pool.alloc_item();

		thread_scoped_lock lock(waiter_map_lock);
		waiter_map.insert(WaiterMap::value_type(tag, waiter));

		return waiter;
	}

	/* send something from any thread */
	bool send_item(CyclesRPCCallBase &item, Waiter *w)
	{
		/* if we need to block this thread until response comes back,
		 * we need to register for unblock before sending */

		Waiter *waiter = NULL;
		if (item.send_request())
			waiter = register_for_unblock(item.get_call_id());

		boost::system::error_code send_err;

		RPCHeader header = item.make_call_header();
		CyclesRPCCallBase::ParameterBuffer parameters = item.get_parameters();
		CyclesRPCCallBase::ParameterBuffer blob = item.get_blob();

		thread_scoped_lock lock(send_lock);
		LOG(INFO) << "SENDING " << item.get_call_id_name();

		boost::asio::write(socket,
				boost::asio::buffer(&header, sizeof(header)),
				send_err);

		if(send_err)
			DLOG(INFO) << "SEND  ERROR" << send_err.message();

		boost::asio::write(socket,
				boost::asio::buffer(parameters.first, parameters.second),
				send_err);

		if(send_err)
			DLOG(INFO) << "SEND  ERROR" << send_err.message();

		boost::asio::write(socket,
				boost::asio::buffer(blob.first, blob.second),
				send_err);

		if(send_err)
			DLOG(INFO) << "SEND  ERROR" << send_err.message();
		DLOG(INFO) << "DONE SENDING " << item.get_call_id_name() << " to " << socket.remote_endpoint().address();

		lock.unlock();
		if (item.send_request()) {
			DLOG(INFO) << "EXPECTING a REPLY";
			w = waiter;
			return true;
		}
		else
			return false;

	}

	/* receive stream implementation */

	void post_async_recv_header()
	{
		DLOG(INFO) << "REGISTERING CALLBACK FOR RECEIVING A HEADER";

		recv_state = receiving_header;

		boost::asio::async_read(socket,
				boost::asio::buffer(&recv_header, sizeof(recv_header)),
				boost::bind(&RPCStreamManager::handle_recv_header, this,
				boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void handle_recv_header(const boost::system::error_code& error, size_t size)
	{
		if(error == boost::asio::error::eof)
			return;
		if(error != 0 || size < 1){
			DLOG(ERROR) << "Error receiving header";
			post_async_recv_header();
			return;
		}
		DLOG(INFO) << "Receiving header " << recv_header.id;
		if( recv_header.length == 0 && recv_header.blob_len == 0) {
			/* Packet claims to be done */
			deliver_recv();
			post_async_recv_header();
		} else if (recv_header.length > 0) {
			post_async_recv_args();
		}
		else if (recv_header.blob_len > 0) {
			//post_async_recv_blob();
			DLOG(INFO) << "IGNORE BLOB LENGHT" << recv_header.blob_len;
			deliver_recv();
		}
		else {
			DLOG(ERROR) << "Empty request header!";
			post_async_recv_header();
		}
	}

	void post_async_recv_args()
	{
		DLOG(INFO) << "REGISTERING CALLBACK FOR RECEIVING ARGS";

		recv_state = receiving_args;

		/* expand buffer if needed */
		if (recv_args_buffer.size() < recv_header.length)
			recv_args_buffer.resize(recv_header.length);

		boost::asio::async_read(socket,
				boost::asio::buffer(&recv_args_buffer[0], recv_header.length),
				boost::bind(&RPCStreamManager::handle_recv_args, this,
				boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void handle_recv_args(const boost::system::error_code& error, size_t size)
	{
		if (recv_header.blob_len > 0) {
			post_async_recv_blob();
		} else {
			/* Packet claims to be done */
			deliver_recv();
			post_async_recv_header();
		}
	}

	void post_async_recv_blob()
	{
		DLOG(INFO) << "REGISTERING CALLBACK FOR RECEIVING BLOB";

		recv_state = receiving_blob;

		/* expand buffer if needed */
		if (recv_blob_buffer.size() < recv_header.blob_len)
			recv_blob_buffer.resize(recv_header.blob_len);

		boost::asio::async_read(socket,
				boost::asio::buffer(&recv_blob_buffer[0], recv_header.blob_len),
				boost::bind(&RPCStreamManager::handle_recv_blob, this,
				boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void handle_recv_blob(const boost::system::error_code& error, size_t size)
	{
		recv_state = receiving_header;

		if(error ==  0){
			deliver_recv();
		} else {
			DLOG(ERROR) << "Some network error";
		}
		post_async_recv_header();
	}

	void deliver_recv()
	{
		CyclesRPCCallBase *item = CyclesRPCCallFactory::decode_item(
				recv_header, recv_args_buffer, recv_blob_buffer);

		LOG(INFO) << "DECODING ITEM " << item->get_call_id_name();
		/* inspect header to see if this is a response */
		if (recv_header.id & CyclesRPCCallBase::response_flag) {
			/* it is a response */
			DLOG(INFO) << "GOT A VALID RESPONSE";
			/* wake up waiter */
			WaiterMap::iterator waiter = waiter_map.find(recv_header.tag);
			waiter->second->notify();
			waiter_map.erase(waiter);
		}
		else {
			/* it is a request */
			recv_queue.push(item);
			LOG(INFO) << "PUSH ITEM " << item->get_call_id_name();
		}
	}

	boost::system::error_code connect_impl(const std::string &address)
	{
		boost::system::error_code err;
		stringstream portstr;

		/* use specified port if address with host:port format was passed */
		std::string::const_iterator colon = std::find(address.begin(), address.end(), ':');
		if (colon != address.end())
			portstr.str(std::string(colon + 1, address.end()));
		else
			portstr << SERVER_PORT;

		tcp::resolver resolver(socket.get_io_service());
		tcp::resolver::query query(address, portstr.str());

		/* try all of the addresses the resolver found */
		for (tcp::resolver::iterator e, i = resolver.resolve(query, err); i != e; ++i) {
			/* if resolver encountered an error, return it */
			if (err)
				return err;

			/* try to connect to the address */
			socket.connect(*i, err);

			/* if it succeeded, stop trying addresses */
			if (!err)
				break;

			/* close the failed socket */
			socket.close();
		}

		return err;
	}

public:
	/* constructor called when operating as a server that accepts
	 * an inbound connection from client */
	RPCStreamManager(tcp::socket& incoming)
		: socket(incoming)
		, recv_args_buffer(CyclesRPCCallBase::max_payload, 0)
	{
	}

	std::string connect_to_server(const std::string &address)
	{
		std::string err;
		boost::system::error_code error_code = connect_impl(address);

		err = error_code.message();
		return err;
	}

	void send_call(CyclesRPCCallBase &call)
	{
		DLOG(INFO) << "send_call() " << call.get_call_id_name();
		Waiter *w;
		if(send_item(call, w)) {
			DLOG(INFO) << "waiting for response " << call.get_call_id_name();
			//w->wait(); /* Blocking till we get it */
		}
	}

	void wait_for()
	{
	}


	void listen(){
		post_async_recv_header();
	}

	CyclesRPCCallBase *wait_request()
	{
		CyclesRPCCallBase *item;
		recv_queue.pop(item);
		DLOG(INFO) << "POP " << item->get_call_id_name();
		return item;
	}
};

/* Server auto discovery */

class ServerDiscovery {
public:
	ServerDiscovery(bool discover = false)
	: listen_socket(io_service), collect_servers(false)
	{
		/* setup listen socket */
		listen_endpoint.address(boost::asio::ip::address_v4::any());
		listen_endpoint.port(DISCOVER_PORT);

		listen_socket.open(listen_endpoint.protocol());

		boost::asio::socket_base::reuse_address option(true);
		listen_socket.set_option(option);

		listen_socket.bind(listen_endpoint);

		/* setup receive callback */
		async_receive();

		/* start server discovery */
		if(discover) {
			collect_servers = true;
			servers.clear();

			broadcast_message(DISCOVER_REQUEST_MSG);
		}

		/* start thread */
		work = new boost::asio::io_service::work(io_service);
		thread = new boost::thread(boost::bind(&boost::asio::io_service::run, &io_service));
	}

	~ServerDiscovery()
	{
		io_service.stop();
		thread->join();
		delete thread;
		delete work;
	}

	vector<string> get_server_list()
	{
		vector<string> result;

		mutex.lock();
		result = vector<string>(servers.begin(), servers.end());
		mutex.unlock();

		return result;
	}

private:
	void handle_receive_from(const boost::system::error_code& error, size_t size)
	{
		if(error) {
			DLOG(INFO) << "Server discovery receive error: " << error.message();
			return;
		}

		if(size > 0) {
			string msg = string(receive_buffer, size);

			/* handle incoming message */
			if(collect_servers) {
				if(msg == DISCOVER_REPLY_MSG) {
					string address = receive_endpoint.address().to_string();

					mutex.lock();

					/* add address if it's not already in the list */
					bool found = std::find(servers.begin(), servers.end(),
							address) != servers.end();

					if(!found)
						servers.push_back(address);

					mutex.unlock();
				}
			}
			else {
				/* reply to request */
				if(msg == DISCOVER_REQUEST_MSG)
					broadcast_message(DISCOVER_REPLY_MSG);
			}
		}

		async_receive();
	}

	void async_receive()
	{
		listen_socket.async_receive_from(
			boost::asio::buffer(receive_buffer), receive_endpoint,
			boost::bind(&ServerDiscovery::handle_receive_from, this,
			boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void broadcast_message(const string& msg)
	{
		/* setup broadcast socket */
		boost::asio::ip::udp::socket socket(io_service);

		socket.open(boost::asio::ip::udp::v4());

		boost::asio::socket_base::broadcast option(true);
		socket.set_option(option);

		boost::asio::ip::udp::endpoint broadcast_endpoint(
			boost::asio::ip::address::from_string("255.255.255.255"), DISCOVER_PORT);

		/* broadcast message */
		socket.send_to(boost::asio::buffer(msg), broadcast_endpoint);
	}

	/* network service and socket */
	boost::asio::io_service io_service;
	boost::asio::ip::udp::endpoint listen_endpoint;
	boost::asio::ip::udp::socket listen_socket;

	/* threading */
	boost::thread *thread;
	boost::asio::io_service::work *work;
	boost::mutex mutex;

	/* buffer and endpoint for receiving messages */
	char receive_buffer[256];
	boost::asio::ip::udp::endpoint receive_endpoint;

	// os, version, devices, status, host name, group name, ip as far as fields go
	struct ServerInfo {
		string blender_version;
		string os;
		int device_count;
		string status;
		string host_name;
		string group_name;
		string host_addr;
	};

	/* collection of server addresses in list */
	bool collect_servers;
	vector<string> servers;
};

CCL_NAMESPACE_END

#endif

#endif /* __DEVICE_NETWORK_H__ */

