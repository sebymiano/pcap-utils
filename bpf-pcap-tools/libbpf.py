# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause 
# Copyright (c) 2023 Sebastiano Miano <mianosebastiano@gmail.com>

import ctypes as ct
import pathlib
import os

class Libbpf:
    class bpf_get_fd_by_id_opts(ct.Structure):
        _fields_ = [
            ('sz', ct.c_ulong),
            ('open_flags', ct.c_uint32),
            ('pad', ct.c_ulong),
        ]

    class bpf_prog_info(ct.Structure):
        _fields_ = [
            ("type", ct.c_uint32),
            ("id", ct.c_uint32),
            ("tag", ct.c_char * 8),
            ("jited_prog_len", ct.c_uint32),
            ("xlated_prog_len", ct.c_uint32),
            ("jited_prog_insns", ct.c_void_p),
            ("xlated_prog_insns", ct.c_void_p),
            ("load_time", ct.c_uint64),
            ("created_by_uid", ct.c_uint32),
            ("nr_map_ids", ct.c_uint32),
            ("map_ids", ct.c_uint32 * 0),
            ("name", ct.c_char * 16),
            ("ifindex", ct.c_uint32),
            ("gpl_compatible", ct.c_uint32),
            ("netns_dev", ct.c_uint64),
            ("netns_ino", ct.c_uint64),
            ("nr_jited_ksyms", ct.c_uint32),
            ("nr_jited_func_lens", ct.c_uint32),
            ("jited_ksyms", ct.c_void_p),
            ("jited_func_lens", ct.c_void_p),
            ("btf_id", ct.c_uint32),
            ("func_info_rec_size", ct.c_uint32),
            ("func_info", ct.c_void_p),
            ("nr_func_info", ct.c_uint32),
            ("nr_line_info", ct.c_uint32),
            ("line_info", ct.c_void_p),
            ("jited_line_info", ct.c_void_p),
            ("nr_jited_line_info", ct.c_uint32),
            ("line_info_rec_size", ct.c_uint32),
            ("jit_line_info_rec_size", ct.c_uint32),
            ("nr_prog_tags", ct.c_uint32),
            ("prog_tags", ct.c_void_p),
            ("run_time_ns", ct.c_uint64),
            ("run_cnt", ct.c_uint64),
            ("recursion_misses", ct.c_uint64),
            ("verified_insns", ct.c_uint32),
            ("attach_btf_obj_id", ct.c_uint32),
            ("attach_btf_id", ct.c_uint32)]
        
    class bpf_map_info(ct.Structure):
        _fields_ = [
            ("type", ct.c_uint32),
            ("id", ct.c_uint32),
            ("key_size", ct.c_uint32),
            ("value_size", ct.c_uint32),
            ("max_entries", ct.c_uint32),
            ("map_flags", ct.c_uint32),
            ("name", ct.c_char * 16),
            ("ifindex", ct.c_uint32),
            ("btf_vmlinux_value_type_id", ct.c_uint32),
            ("netns_dev", ct.c_uint64),
            ("netns_ino", ct.c_uint64),
            ("btf_id", ct.c_uint32),
            ("btf_key_type_id", ct.c_uint32),
            ("btf_value_type_id", ct.c_uint32),
            ("alignment", ct.c_uint32),
            ("max_extra", ct.c_uint64)]

    def __init__(self, libbpf_lib_path):
        if not os.path.isfile(libbpf_lib_path):
            raise Exception(f"{libbpf_lib_path} not found. Please build libbpf first.")

        self.lib = ct.CDLL(libbpf_lib_path, use_errno=True)

        self.lib.bpf_map_get_fd_by_id.restype = ct.c_int
        self.lib.bpf_map_get_fd_by_id.argtypess = [ct.c_uint32]
        self.lib.bpf_map_get_fd_by_id_opts.restype = ct.c_int
        self.lib.bpf_map_get_fd_by_id_opts.argtypess = [ct.c_uint32, ct.POINTER(bpf_get_fd_by_id_opts)]

        self.lib.bpf_prog_get_fd_by_id.restype = ct.c_int
        self.lib.bpf_prog_get_fd_by_id.argtypess = [ct.c_uint32]
        self.lib.bpf_map_get_fd_by_id_opts.restype = ct.c_int
        self.lib.bpf_map_get_fd_by_id_opts.argtypess = [ct.c_uint32, ct.POINTER(bpf_get_fd_by_id_opts)]

        self.lib.bpf_btf_get_fd_by_id.restype = ct.c_int
        self.lib.bpf_btf_get_fd_by_id.argtypess = [ct.c_uint32]
        self.lib.bpf_btf_get_fd_by_id_opts.restype = ct.c_int
        self.lib.bpf_btf_get_fd_by_id_opts.argtypess = [ct.c_uint32, ct.POINTER(bpf_get_fd_by_id_opts)]

        self.lib.bpf_obj_get_info_by_fd.restype = ct.c_int
        self.lib.bpf_obj_get_info_by_fd.argtypess = [ct.c_int, ct.c_void_p, ct.POINTER(ct.c_uint32)]

        self.lib.bpf_map_lookup_elem.restype = ct.c_int
        self.lib.bpf_map_lookup_elem.argtypess = [ct.c_int, ct.c_void_p, ct.c_void_p]

        self.lib.bpf_map_lookup_elem_flags.restype = ct.c_int
        self.lib.bpf_map_lookup_elem_flags.argtypess = [ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_uint64]

        self.lib.bpf_map_lookup_and_delete_elem.restype = ct.c_int
        self.lib.bpf_map_lookup_and_delete_elem.argtypess = [ct.c_int, ct.c_void_p, ct.c_void_p]

        self.lib.bpf_map_lookup_and_delete_elem_flags.restype = ct.c_int
        self.lib.bpf_map_lookup_and_delete_elem_flags.argtypess = [ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_uint64]

        self.lib.bpf_map_update_elem.restype = ct.c_int
        self.lib.bpf_map_update_elem.argtypess = [ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_uint64]

        self.lib.bpf_map_delete_elem.restype = ct.c_int
        self.lib.bpf_map_delete_elem.argtypess = [ct.c_int, ct.c_void_p]

        self.lib.bpf_map_delete_elem_flags.restype = ct.c_int
        self.lib.bpf_map_delete_elem_flags.argtypess = [ct.c_int, ct.c_void_p, ct.c_uint64]

        self.lib.bpf_map_get_next_key.restype = ct.c_int
        self.lib.bpf_map_get_next_key.argtypess = [ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_void_p]

        self.lib.bpf_map_freeze.restype = ct.c_int
        self.lib.bpf_map_freeze.argtypess = [ct.c_int]

        self.lib.bpf_prog_attach.restype = ct.c_int
        self.lib.bpf_prog_attach.argtypes = [ct.c_int, ct.c_int, ct.c_int, ct.c_uint]

        self.lib.bpf_prog_detach2.restype = ct.c_int
        self.lib.bpf_prog_detach2.argtypes = [ct.c_int, ct.c_int, ct.c_int]

        self.lib.bpf_prog_get_next_id.restype = ct.c_int
        self.lib.bpf_prog_get_next_id.argtypes = [ct.c_uint32, ct.c_uint32]

        self.lib.bpf_map_get_next_id.restype = ct.c_int
        self.lib.bpf_map_get_next_id.argtypes = [ct.c_uint32, ct.c_uint32]

        self.lib.bpf_btf_get_next_id.restype = ct.c_int
        self.lib.bpf_btf_get_next_id.argtypes = [ct.c_uint32, ct.c_uint32]

        self.lib.bpf_link_get_next_id.restype = ct.c_int
        self.lib.bpf_link_get_next_id.argtypes = [ct.c_uint32, ct.c_uint32]

        self.lib.bpf_prog_get_info_by_fd.restype = ct.c_int
        self.lib.bpf_prog_get_info_by_fd.argtypes = [ct.c_int, ct.POINTER(bpf_prog_info), ct.POINTER(ct.c_uint32)]

        self.lib.bpf_map_get_info_by_fd.restype = ct.c_int
        self.lib.bpf_map_get_info_by_fd.argtypes = [ct.c_int, ct.POINTER(bpf_map_info), ct.POINTER(ct.c_uint32)]