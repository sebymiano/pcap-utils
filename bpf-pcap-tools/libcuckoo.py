# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause 
# Copyright (c) 2023 Sebastiano Miano <mianosebastiano@gmail.com>

import ctypes as ct
import pathlib
import os

CUCKOO_ERROR_MSG_SIZE = 256
class Libcuckoo:
    class CuckooError(ct.Structure):
        _fields_ = [
            ('error_code', ct.c_int),
            ('error_msg', ct.c_char * CUCKOO_ERROR_MSG_SIZE)
        ]

    class CuckooHashmap(ct.Structure):
        _fields_ = [
            ('map_fd', ct.c_int),
            ('map_id', ct.c_int),
            ('map_type', ct.c_int),
            ('num_cpus', ct.c_uint),
            ('key_size', ct.c_size_t),
            ('value_size', ct.c_size_t),
            ('max_entries', ct.c_uint32),
            ('hash_cell_size', ct.c_size_t),
            ('table_size', ct.c_size_t),
            ('entire_map_size', ct.c_size_t)
        ]

    def __init__(self, libcuckoo_lib_path, libbpf_lib_path=None):
        if not os.path.isfile(libcuckoo_lib_path):
            raise Exception(f"{libcuckoo_lib_path} not found. Please build libcuckoo first.")
        
        if libbpf_lib_path is not None and not os.path.isfile(libbpf_lib_path):
            raise Exception(f"{libbpf_lib_path} not found. Please build libbpf first.")
        
        ct.CDLL(libbpf_lib_path, use_errno=True)
        self.__lib = ct.CDLL(libcuckoo_lib_path, use_errno=True)

        self.init_by_fd = self.__define_init_by_fd()
        self.init_by_id = self.__define_init_by_id()
        self.insert = self.__define_insert()
        self.lookup = self.__define_lookup()
        self.delete = self.__define_delete()
        self.destroy = self.__define_destroy()

    def __define_init_by_fd(self):
        self.__lib.cuckoo_table_init_by_fd.argtypes = [ct.c_int, ct.c_size_t, ct.c_size_t, ct.c_uint32, ct.c_bool, ct.POINTER(Libcuckoo.CuckooError)]
        self.__lib.cuckoo_table_init_by_fd.restype = ct.POINTER(Libcuckoo.CuckooHashmap)
        def init_by_fd(map_fd, key_size, value_size, max_entries, aligned=False):
            err = self.CuckooError()
            hashmap = self.__lib.cuckoo_table_init_by_fd(map_fd, key_size, value_size, max_entries, ct.c_bool(aligned), ct.byref(err))
            if not hashmap:
                raise Exception(f"Failed to initialize cuckoo hashmap: error_code={err.error_code}, error_msg={err.error_msg.decode()}")
            return hashmap
        
        return init_by_fd
    
    def __define_init_by_id(self):
        self.__lib.cuckoo_table_init_by_id.argtypes = [ct.c_int, ct.c_size_t, ct.c_size_t, ct.c_uint32, ct.c_bool, ct.POINTER(Libcuckoo.CuckooError)]
        self.__lib.cuckoo_table_init_by_id.restype = ct.POINTER(Libcuckoo.CuckooHashmap)
        def init_by_id(map_id, key_size, value_size, max_entries, aligned=False):
            err = self.CuckooError()
            hashmap = self.__lib.cuckoo_table_init_by_id(map_id, key_size, value_size, max_entries, aligned, ct.byref(err))
            if not hashmap:
                raise Exception(f"Failed to initialize cuckoo hashmap: error_code={err.error_code}, error_msg={err.error_msg.decode()}")
            return hashmap
        
        return init_by_id
    
    def __define_insert(self):
        self.__lib.cuckoo_insert.argtypes = [ct.POINTER(Libcuckoo.CuckooHashmap), ct.c_void_p, ct.c_void_p, ct.c_size_t, ct.c_size_t, ct.POINTER(Libcuckoo.CuckooError)]
        self.__lib.cuckoo_insert.restype = ct.c_int
        def insert(map, key, value, key_size, value_size):
            err = self.CuckooError()
            ret = self.__lib.cuckoo_insert(map, key, value, key_size, value_size, ct.byref(err))
            if ret != 0:
                raise Exception(f"Failed to insert key-value pair: error_code={err.error_code}, error_msg={err.error_msg.decode()}")
            return ret
        return insert

    def __define_lookup(self):
        self.__lib.cuckoo_lookup.argtypes = [ct.POINTER(Libcuckoo.CuckooHashmap), ct.c_void_p, ct.c_size_t, ct.c_void_p, ct.c_size_t, ct.POINTER(ct.c_bool), ct.c_size_t, ct.POINTER(Libcuckoo.CuckooError)]
        self.__lib.cuckoo_lookup.restype = ct.c_int
        def lookup(map, key, key_size, value_to_read, value_to_read_size, value_found, value_found_size):
            err = self.CuckooError()
            ret = self.__lib.cuckoo_lookup(map, key, key_size, value_to_read, value_to_read_size, value_found, value_found_size, ct.byref(err))
            if ret != 0:
                raise Exception(f"Failed to lookup key: error_code={err.error_code}, error_msg={err.error_msg.decode()}")
            return ret
        return lookup

    def __define_delete(self):
        self.__lib.cuckoo_delete.argtypes = [ct.POINTER(Libcuckoo.CuckooHashmap), ct.c_void_p, ct.c_size_t, ct.POINTER(Libcuckoo.CuckooError)]
        self.__lib.cuckoo_delete.restype = ct.c_int
        def delete(map, key, key_size):
            err = self.CuckooError()
            ret = self.__lib.cuckoo_delete(map, key, key_size, ct.byref(err))
            if ret != 0:
                raise Exception(f"Failed to delete key: error_code={err.error_code}, error_msg={err.error_msg.decode()}")
            return ret
        return delete

    def __define_destroy(self):
        self.__lib.cuckoo_table_destroy.argtypes = [ct.POINTER(Libcuckoo.CuckooHashmap)]
        self.__lib.cuckoo_table_destroy.restype = None
        def destroy(hashmap):
            self.__lib.cuckoo_table_destroy(hashmap)
        return destroy
           