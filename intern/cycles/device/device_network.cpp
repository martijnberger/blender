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

#include "device.h"
#include "device_intern.h"
#include "device_network.h"

#include "util_foreach.h"
#include "util_logging.h"

#if defined(WITH_NETWORK)

CCL_NAMESPACE_BEGIN


typedef map<device_ptr, device_ptr> PtrMap;
typedef vector<uint8_t> DataVector;
typedef map<device_ptr, DataVector> DataMap;

/* tile list */
typedef vector<RenderTile> TileList;


CyclesRPCCallBase *CyclesRPCCallFactory::decode_item(RPCHeader* header,
		ByteVector* args_buffer,
		ByteVector* blob_buffer)
{
	switch (header->id)
	{
	case CyclesRPCCallBase::mem_alloc_request:
		return new RPCCall_mem_alloc(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::stop_request:
		return new RPCCall_stop(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::mem_mem_copy_to_request:
		return new RPCCall_mem_copy_to(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::mem_copy_from_request:
		return new RPCCall_mem_copy_from(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::mem_zero_request:
		return new RPCCall_mem_zero(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::mem_free_request:
		return new RPCCall_mem_free(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::const_copy_to_request:
		return new RPCCall_const_copy_to(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::tex_alloc_request:
		return new RPCCall_tex_alloc(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::tex_free_request:
		return new RPCCall_tex_free(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::load_kernels_request:
		return new RPCCall_load_kernels(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::task_add_request:
		return new RPCCall_task_add(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::task_wait_request:
		return new RPCCall_task_wait(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::task_cancel_request:
		return new RPCCall_task_cancel(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::acquire_tile_request:
		return new RPCCall_acquire_tile(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::release_tile_request:
		return new RPCCall_release_tile(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::task_wait_done_request:
		return new RPCCall_task_wait_done(header, args_buffer, blob_buffer);

	/* responses */
	case CyclesRPCCallBase::mem_alloc_response:
		return new RPCCall_mem_alloc_response(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::acquire_tile_response:
		return new RPCCall_acquire_tile_response(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::release_tile_response:
		return new RPCCall_release_tile_response(header, args_buffer, blob_buffer);

	case CyclesRPCCallBase::load_kernels_response:
		return new RPCCall_load_kernels(header, args_buffer, blob_buffer);

	default:
		assert(!"Should not happen!");
		return NULL;
	}
}

void CyclesRPCCallFactory::rpc_mem_alloc(RPCStreamManager& stream,
		device_memory& mem, MemoryType type)
{
	RPCCall_mem_alloc call(mem, type);
	stream.send_call(call);
}

void CyclesRPCCallFactory::rpc_stop(RPCStreamManager& stream)
{
	RPCCall_stop call;
	stream.send_call(call);
}

void CyclesRPCCallFactory::rpc_mem_copy_to(RPCStreamManager& stream, device_memory& mem)
{
	RPCCall_mem_copy_to call(mem);
}

void CyclesRPCCallFactory::rpc_mem_copy_from(RPCStreamManager& stream,
		device_memory& mem, int y, int w, int h, int elem, void *output)
{
	RPCCall_mem_copy_from call(mem, y, w, h, elem, output);
	/* FIXME: need to get a call id to wait for here */
	stream.send_call(call);
	stream.wait_for();
}

void CyclesRPCCallFactory::rpc_mem_zero(RPCStreamManager& stream,
		device_memory& mem)
{
	RPCCall_mem_zero call(mem);
	stream.send_call(call);
}

void CyclesRPCCallFactory::rpc_mem_free(RPCStreamManager& stream,
		device_memory& mem)
{
	RPCCall_mem_free call(mem);
	stream.send_call(call);
}

void CyclesRPCCallFactory::rpc_const_copy_to(RPCStreamManager& stream,
		const std::string& name, void *data, size_t size)
{
	DLOG(INFO) << "const_copy_to_call " << name << " " << size;
	RPCCall_const_copy_to call(name, data, size);
	stream.send_call(call);
}

void CyclesRPCCallFactory::rpc_tex_alloc(RPCStreamManager& stream,
		const std::string& name, device_memory& mem,
		bool interpolation, bool periodic)
{
	RPCCall_tex_alloc call(name, mem, interpolation, periodic);

	stream.send_call(call);
}

void CyclesRPCCallFactory::rpc_tex_free(RPCStreamManager& stream,
		device_memory& mem)
{
	RPCCall_tex_free call(mem);
	stream.send_call(call);
}

bool CyclesRPCCallFactory::rpc_load_kernels(RPCStreamManager& stream,
		bool experimental)
{
	RPCCall_load_kernels call(experimental);

	stream.send_call(call);
	return true; // Lets speculate on succes, next calls might return error
}

void CyclesRPCCallFactory::rpc_task_add(RPCStreamManager& stream,
		DeviceTask& task)
{
	RPCCall_task_add call(task);
	stream.send_call(call);
}

void CyclesRPCCallFactory::rpc_task_wait(RPCStreamManager& stream)
{
	RPCCall_task_wait call;
	stream.send_call(call);
}

void CyclesRPCCallFactory::rpc_task_cancel(RPCStreamManager& stream)
{
	RPCCall_task_cancel call;
	stream.send_call(call);
}

void CyclesRPCCallFactory::rpc_acquire_tile_response(RPCStreamManager &stream,
													 CyclesRPCCallBase *request,
													 bool retval, RenderTile &tile)
{

}

void CyclesRPCCallFactory::rpc_release_tile(RPCStreamManager &stream, RenderTile &tile)
{

}

/* search a list of tiles and find the one that matches the passed render tile */
static TileList::iterator tile_list_find(TileList& tile_list, RenderTile& tile)
{
	for(TileList::iterator it = tile_list.begin(); it != tile_list.end(); ++it)
		if(tile.x == it->x && tile.y == it->y && tile.start_sample == it->start_sample)
			return it;
	return tile_list.end();
}

class NetworkDevice : public Device
{
public:
	boost::asio::io_service io_service;
	tcp::socket socket;
	device_ptr mem_counter;

	DeviceTask the_task; /* todo: handle multiple tasks */

	boost::thread *io_service_thread;
	RPCStreamManager rpc_stream;

	NetworkDevice(DeviceInfo& info, Stats &stats, const char *address)
		: Device(info, stats, true)
		, socket(io_service)
		, rpc_stream(socket)
	{
		rpc_stream.listen();
		io_service_thread = new boost::thread(boost::bind(&boost::asio::io_service::run, &io_service));
		mem_counter = 0;
		rpc_stream.connect_to_server(address);
	}

	~NetworkDevice()
	{
		CyclesRPCCallFactory::rpc_stop(rpc_stream);
		io_service_thread->interrupt();
		io_service_thread->join();
	}



	void mem_alloc(device_memory& mem, MemoryType type)
	{
		DLOG(INFO) << "mem_alloc()";
		mem.device_pointer = ++mem_counter;
		CyclesRPCCallFactory::rpc_mem_alloc(rpc_stream, mem, type);
	}

	void mem_copy_to(device_memory& mem)
	{
		DLOG(INFO) << "mem_copy_to()";
		CyclesRPCCallFactory::rpc_mem_copy_to(rpc_stream, mem);
	}

	void mem_copy_from(device_memory& mem, int y, int w, int h, int elem)
	{
		DLOG(INFO) << "mem_copy_from()";
		CyclesRPCCallFactory::rpc_mem_copy_from(rpc_stream,
				mem, y, w, h, elem, (void*)mem.data_pointer);
	}

	void mem_zero(device_memory& mem)
	{
		DLOG(INFO) << "mem_zero()";
		CyclesRPCCallFactory::rpc_mem_zero(rpc_stream, mem);
	}

	void mem_free(device_memory& mem)
	{
		DLOG(INFO) << "mem_free()";
		if(mem.device_pointer) {
			CyclesRPCCallFactory::rpc_mem_free(rpc_stream, mem);
			mem.device_pointer = 0;
		}
	}

	void const_copy_to(const char *name, void *data, size_t size)
	{
		DLOG(INFO) << "const_copy_to( " << name << " )";
		CyclesRPCCallFactory::rpc_const_copy_to(rpc_stream,
			std::string(name), data, size);
	}

	void tex_alloc(const char *name, device_memory& mem, bool interpolation, bool periodic)
	{
		VLOG(1) << "Texture allocate: " << name << ", " << mem.memory_size() << " bytes.";
		mem.device_pointer = ++mem_counter;

		CyclesRPCCallFactory::rpc_tex_alloc(rpc_stream, name, mem, interpolation, periodic);
	}

	void tex_free(device_memory& mem)
	{
		DLOG(INFO) << "tex_free( " << std::hex << mem.device_pointer << ")";
		if(mem.device_pointer) {
			CyclesRPCCallFactory::rpc_tex_free(rpc_stream, mem);
			mem.device_pointer = 0;
		}
	}

	bool load_kernels(bool experimental)
	{
		DLOG(INFO) << "load_kernels()";
		bool res = CyclesRPCCallFactory::rpc_load_kernels(rpc_stream, experimental);
		LOG(INFO) << "load_kernels ->" << res;
		return res;
	}

	void task_add(DeviceTask& task)
	{
		DLOG(INFO) << "task_add()";
		the_task = task;

		DLOG(INFO) << "Task: x " << task.x << ", y: " << task.y << ", w: " << task.w << ", h" << task.h;
		CyclesRPCCallFactory::rpc_task_add(rpc_stream, task);
	}

	void task_wait()
	{
		DLOG(INFO) << "task_wait()";
		CyclesRPCCallFactory::rpc_task_wait(rpc_stream);

		TileList the_tiles;

		/* todo: run this threaded for connecting to multiple clients */
		bool done = false;
		do {

			RenderTile tile;

			DLOG(INFO) << "Seending wait request .. waiting for response";

			CyclesRPCCallBase *request = rpc_stream.wait_request();


			DLOG(INFO) << "  GOT response for wait request";

			switch (request->get_call_id())
			{
				case CyclesRPCCallBase::acquire_tile_request:
				{
					if(the_task.acquire_tile(this, tile)) { /* write return as bool */
						the_tiles.push_back(tile);

						CyclesRPCCallFactory::rpc_acquire_tile_response(rpc_stream, request, true, tile);
					}
					else {
						CyclesRPCCallFactory::rpc_acquire_tile_response(rpc_stream, request, false, tile);
					}
					break;
				}
				case CyclesRPCCallBase::release_tile_request:
				{
					request->read(tile);

					TileList::iterator it = tile_list_find(the_tiles, tile);
					if(it != the_tiles.end()) {
						tile.buffers = it->buffers;
						the_tiles.erase(it);
					}

					assert(tile.buffers != NULL);

					the_task.release_tile(tile);

					/* FIXME: what's going on here? */

					//RPCSend snd(socket, "release_tile");
					//snd.write();
					//lock.unlock();

					break;
				}
				case CyclesRPCCallBase::task_wait_done_request:
					done = true;
					break;

				default:
					break;
				}
		} while (!done);
		DLOG(INFO) << "task_wait: done";
	}

	void task_cancel()
	{
		DLOG(INFO) << "task_cancel()";
		CyclesRPCCallFactory::rpc_task_cancel(rpc_stream);
	}

	int get_split_task_count(DeviceTask& task){
		DLOG(INFO) << "get_split_task_count()";
		return 0;
		/*FIX dummy implementation */
	}
};

Device *device_network_create(DeviceInfo& info, Stats &stats, const char *address)
{
	return new NetworkDevice(info, stats, address);
}

void device_network_info(vector<DeviceInfo>& devices)
{
	DeviceInfo info;

	info.type = DEVICE_NETWORK;
	info.description = "Network Device";
	info.id = "NETWORK";
	info.num = 0;
	info.advanced_shading = true; /* todo: get this info from device */
	info.pack_images = false;

	devices.push_back(info);
}

class DeviceServer {
public:
	thread_mutex lock;

	DeviceServer(Device *device_, tcp::socket& socket_)
		: device(device_), rpc_stream(socket_)
	{
		io_service = &(socket_.get_io_service());
		 thread_scoped_lock l(lock); // make the mutex lock at least once
	}

	~DeviceServer(){
		io_service_thread->interrupt();
		io_service_thread->join();
	}

	void listen()
	{
		LOG(INFO) << "DEVICE SERVER LISTENING";
		io_service_thread = new boost::thread(boost::bind(&boost::asio::io_service::run, io_service));

		rpc_stream.listen();
		//rpc_stream.wait_for();
		/* receive remote function calls */
		for(;;) {
			DLOG(INFO) << "RPC_stream.wait_request()";
			CyclesRPCCallBase *request = rpc_stream.wait_request();

			if(request->get_call_id() == CyclesRPCCallBase::stop_request) {
				io_service->reset();
				break;
			}
			process(*request);

		}
	}

protected:
	/* create a memory buffer for a device buffer and insert it into mem_data */
	DataVector &data_vector_insert(device_ptr client_pointer, size_t data_size)
	{
		/* create a new DataVector and insert it into mem_data */
		pair<DataMap::iterator,bool> data_ins = mem_data.insert(
				DataMap::value_type(client_pointer, DataVector()));

		/* make sure it was a unique insertion */
		assert(data_ins.second);

		/* get a reference to the inserted vector */
		DataVector &data_v = data_ins.first->second;

		/* size the vector */
		data_v.resize(data_size);

		return data_v;
	}

	DataVector &data_vector_find(device_ptr client_pointer)
	{
		DataMap::iterator i = mem_data.find(client_pointer);
		assert(i != mem_data.end());
		return i->second;
	}

	/* setup mapping and reverse mapping of client_pointer<->real_pointer */
	void pointer_mapping_insert(device_ptr client_pointer, device_ptr real_pointer)
	{
		pair<PtrMap::iterator,bool> mapins;

		/* insert mapping from client pointer to our real device pointer */
		mapins = ptr_map.insert(PtrMap::value_type(client_pointer, real_pointer));
		assert(mapins.second);

		/* insert reverse mapping from real our device pointer to client pointer */
		mapins = ptr_imap.insert(PtrMap::value_type(real_pointer, client_pointer));
		assert(mapins.second);
	}

	device_ptr device_ptr_from_client_pointer(device_ptr client_pointer)
	{
		PtrMap::iterator i = ptr_map.find(client_pointer);
		assert(i != ptr_map.end());
		return i->second;
	}

	device_ptr device_ptr_from_client_pointer_erase(device_ptr client_pointer)
	{
		PtrMap::iterator i = ptr_map.find(client_pointer);
		assert(i != ptr_map.end());

		device_ptr result = i->second;

		/* erase the mapping */
		ptr_map.erase(i);

		/* erase the reverse mapping */
		PtrMap::iterator irev = ptr_imap.find(result);
		assert(irev != ptr_imap.end());
		ptr_imap.erase(irev);

		/* erase the data vector */
		DataMap::iterator idata = mem_data.find(client_pointer);
		assert(idata != mem_data.end());
		mem_data.erase(idata);

		return result;
	}

	/*  */
	void process(CyclesRPCCallBase& rcv)
	{
		VLOG(1) << "process() " <<  CyclesRPCCallBase::get_call_id_name(rcv.get_call_id());

		switch (rcv.get_call_id()) {
		case CyclesRPCCallBase::mem_alloc_request:
		{
			MemoryType type;
			network_device_memory mem;
			device_ptr client_pointer;

//			rcv.read(mem);
//			rcv.read(type);

			lock.unlock();

			client_pointer = mem.device_pointer;

			/* create a memory buffer for the device buffer */
			size_t data_size = mem.memory_size();
			DataVector &data_v = data_vector_insert(client_pointer, data_size);

			if(data_size)
				mem.data_pointer = (device_ptr)&(data_v[0]);
			else
				mem.data_pointer = 0;

			/* perform the allocation on the actual device */
			device->mem_alloc(mem, type);

			/* store a mapping to/from client_pointer and real device pointer */
			pointer_mapping_insert(client_pointer, mem.device_pointer);
			break;
		}
		case CyclesRPCCallBase::mem_mem_copy_to_request:
		{
			network_device_memory mem;

//			rcv.read(mem);
			lock.unlock();

			device_ptr client_pointer = mem.device_pointer;

			DataVector &data_v = data_vector_find(client_pointer);

			size_t data_size = mem.memory_size();

			/* get pointer to memory buffer	for device buffer */
			mem.data_pointer = (device_ptr)&data_v[0];

			/* copy data from network into memory buffer */
//			rcv.read_buffer((uint8_t*)mem.data_pointer, data_size);

			/* translate the client pointer to a real device pointer */
			mem.device_pointer = device_ptr_from_client_pointer(client_pointer);

			/* copy the data from the memory buffer to the device buffer */
			device->mem_copy_to(mem);
			break;
		}
		case CyclesRPCCallBase::mem_copy_from_request:
		{
			network_device_memory mem;
			int y, w, h, elem;

//			rcv.read(mem);
//			rcv.read(y);
//			rcv.read(w);
//			rcv.read(h);
//			rcv.read(elem);

			device_ptr client_pointer = mem.device_pointer;
			mem.device_pointer = device_ptr_from_client_pointer(client_pointer);

			DataVector &data_v = data_vector_find(client_pointer);

			mem.data_pointer = (device_ptr)&(data_v[0]);

			device->mem_copy_from(mem, y, w, h, elem);

			size_t data_size = mem.memory_size();
			VLOG(1) << "Responding to mem_copy_from size=" << data_size;

			//RPCSend snd(socket);
			//snd.write();
			//snd.write_buffer((uint8_t*)mem.data_pointer, data_size);
			//lock.unlock();
			break;
		}
		case CyclesRPCCallBase::mem_zero_request:
		{
			network_device_memory mem;

//			rcv.read(mem);
			lock.unlock();

			device_ptr client_pointer = mem.device_pointer;
			mem.device_pointer = device_ptr_from_client_pointer(client_pointer);

			DataVector &data_v = data_vector_find(client_pointer);

			mem.data_pointer = (device_ptr)&(data_v[0]);

			device->mem_zero(mem);
			break;
		}
		case CyclesRPCCallBase::mem_free_request:
		{
			network_device_memory mem;
			device_ptr client_pointer;

//			rcv.read(mem);
			lock.unlock();

			client_pointer = mem.device_pointer;

			mem.device_pointer = device_ptr_from_client_pointer_erase(client_pointer);

			device->mem_free(mem);
			break;
		}
		case CyclesRPCCallBase::const_copy_to_request:
		{
			string name_string;
			size_t size;

			rcv.read(name_string);
			rcv.read(size);
			void* buff;
			size_t buff_size;
			rcv.read_blob(&buff, &buff_size);

			LOG_IF(ERROR, (buff_size != size)) << "buff_size != size  " << buff_size << " != " << size;
			lock.unlock();
			DLOG(INFO) << "const_copy_to( " << name_string << "," << buff << "," << size << ")\n";
			device->const_copy_to(name_string.c_str(), buff, size);
			break;
		}
		case CyclesRPCCallBase::tex_alloc_request:
		{
			network_device_memory mem;
			string name;
			bool interpolation;
			bool periodic;
			device_ptr client_pointer;

//			rcv.read(name);
//			rcv.read(mem);
//			rcv.read(interpolation);
//			rcv.read(periodic);
			lock.unlock();

			client_pointer = mem.device_pointer;

			size_t data_size = mem.memory_size();

			DataVector &data_v = data_vector_insert(client_pointer, data_size);

			if(data_size)
				mem.data_pointer = (device_ptr)&(data_v[0]);
			else
				mem.data_pointer = 0;

//			rcv.read_buffer((uint8_t*)mem.data_pointer, data_size);
			device->tex_alloc(name.c_str(), mem, INTERPOLATION_NONE, periodic);

			pointer_mapping_insert(client_pointer, mem.device_pointer);
			break;
		}
		case CyclesRPCCallBase::tex_free_request:
		{
			network_device_memory mem;
			device_ptr client_pointer;

//			rcv.read(mem);
			lock.unlock();

			client_pointer = mem.device_pointer;

			mem.device_pointer = device_ptr_from_client_pointer_erase(client_pointer);

			device->tex_free(mem);
			break;
		}
		case CyclesRPCCallBase::load_kernels_request:
		{
			bool experimental;
			rcv.read(experimental);

			bool result = device->load_kernels(experimental);
			// todo if this is not good we should send something
			break;
		}
		case CyclesRPCCallBase::task_add_request:
		{
			DeviceTask task;

			rcv.dump_buffer();

			rcv.read(task);
			lock.unlock();

			if(task.buffer)
				task.buffer = device_ptr_from_client_pointer(task.buffer);

			if(task.rgba_byte)
				task.rgba_byte = device_ptr_from_client_pointer(task.rgba_byte);

			if(task.rgba_half)
				task.rgba_half = device_ptr_from_client_pointer(task.rgba_half);

			if(task.shader_input)
				task.shader_input = device_ptr_from_client_pointer(task.shader_input);

			if(task.shader_output)
				task.shader_output = device_ptr_from_client_pointer(task.shader_output);

			task.acquire_tile = function_bind(&DeviceServer::task_acquire_tile, this, _1, _2);
			task.release_tile = function_bind(&DeviceServer::task_release_tile, this, _1);
			task.update_progress_sample = function_bind(&DeviceServer::task_update_progress_sample, this);
			task.update_tile_sample = function_bind(&DeviceServer::task_update_tile_sample, this, _1);
			task.get_cancel = function_bind(&DeviceServer::task_get_cancel, this);

			device->task_add(task);
			break;
		}
		case CyclesRPCCallBase::task_wait_request:
		{
			lock.unlock();
			DLOG(INFO) << "Wait request waiting";
			device->task_wait();
			DLOG(INFO) << "DONE WAITING";

			lock.lock();
//			RPCSend snd(socket, "task_wait_done");
//			snd.write();
			lock.unlock();
			break;
		}
		case CyclesRPCCallBase::task_cancel_request:
		{
			lock.unlock();
			device->task_cancel();
			break;
		}
		case CyclesRPCCallBase::acquire_tile_request:
		{
			RenderTile tile;
//			rcv.read(tile);
			lock.unlock();
			//
			break;
		}
		default:
			VLOG(1) << "Unhandled op in CyclesServer::process" << CyclesRPCCallBase::get_call_id_name(rcv.get_call_id());

			raise(SIGTRAP);
		}
		DLOG(INFO) << "Done processing() " << CyclesRPCCallBase::get_call_id_name(rcv.get_call_id());
	}

	bool task_acquire_tile(Device *device, RenderTile& tile)
	{
		//thread_scoped_lock acquire_lock(acquire_mutex);

		bool result = false;

#if 0
		RPCSend snd(socket, "acquire_tile");
		snd.write();

		while(1) {
			thread_scoped_lock lock(rpc_lock);
			RPCReceive rcv(socket);

			if(rcv.name == "acquire_tile") {
//				rcv.read(tile);

				if(tile.buffer) tile.buffer = ptr_map[tile.buffer];
				if(tile.rng_state) tile.rng_state = ptr_map[tile.rng_state];

				result = true;
				break;
			}
			else if(rcv.name == "acquire_tile_none")
				break;
			else
				process(rcv, lock);
		}
#endif
		return result;
	}

	void task_update_progress_sample()
	{
		DLOG(INFO) << "task_update_progress_sample"; /* skip */
	}

	void task_update_tile_sample(RenderTile&)
	{
		DLOG(INFO) << "task_update_progress_sample"; /* skip */
	}

	void task_release_tile(RenderTile& tile)
	{
		//thread_scoped_lock acquire_lock(acquire_mutex);
		if(tile.buffer) tile.buffer = ptr_imap[tile.buffer];
		if(tile.rng_state) tile.rng_state = ptr_imap[tile.rng_state];

		CyclesRPCCallFactory::rpc_release_tile(rpc_stream, tile);

		//thread_scoped_lock lock(rpc_lock);

		while(1) {
			CyclesRPCCallBase *request = rpc_stream.wait_request();

			if (request->get_call_id() == CyclesRPCCallBase::release_tile_request)
				break;

			//process(rcv);
		}
	}

	bool task_get_cancel()
	{
		/* FIXME: return true if there was any network error */


		return false;
	}

	/* properties */
	Device *device;
	RPCStreamManager rpc_stream;
	boost::asio::io_service* io_service;

	/* mapping of remote to local pointer */
	PtrMap ptr_map;
	PtrMap ptr_imap;
	DataMap mem_data;

	//thread_mutex acquire_mutex;

	/* todo: free memory and device (osl) on network error */

private:
	boost::thread *io_service_thread;
};

void HandleAccept(tcp::socket *socket, Device* device, bool* done){
	DeviceServer server(device, *socket);


	string remote_address = socket->remote_endpoint().address().to_string();
	LOG(INFO) << "Connected to remote client at: " << remote_address.c_str();

	server.listen();

	LOG(INFO) << "Disconnected. " << remote_address.c_str();

	*done = true;
}

void Device::server_run()
{
	try {
		/* starts thread that responds to discovery requests */
		ServerDiscovery discovery;

		/* accept connection */
		boost::asio::io_service io_service;
		tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), SERVER_PORT));

		tcp::socket socket(io_service);

		bool done = false;


		DLOG(INFO) << "SETING UP ASYNC ACCEPTOR";
		acceptor.async_accept(socket,boost::bind(&HandleAccept, &socket, this, &done));

		while( !done ){
			io_service.run();
			sleep(1);
		}

	}
	catch(exception& e) {
		fprintf(stderr, "Network server exception: %s\n", e.what());
	}
}


CCL_NAMESPACE_END

#endif
