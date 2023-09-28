//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
#![allow(clippy::not_unsafe_ptr_arg_deref)]
use std::{
    ffi::{c_char, c_int, CStr},
    io::{Read, Write},
    path::PathBuf,
    slice,
};

use bpf_compatible_rs::{generate_current_system_btf_archive_path, tar::Archive};
/// flate2::read 在读数据流上进行操作，包括各种格式的编码器和解码器
/// GzDecoder 针对 gzip文件中单个成员的解码器
/// 此结构对外暴露了一个读的接口，可以通过底层的读取器消费压缩的数据，也可以获取解压的数据
use flate2::read::GzDecoder;
use libc::{c_void, malloc, EILSEQ, EINVAL, EIO, ENOENT, ENOMEM};

/// 包含 btf 信息的 vmlinux 地址
const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

#[no_mangle]
pub extern "C" fn ensure_core_btf_with_tar_binary(
    path: *mut *const c_char,
    tar_bin: *const u8,
    tar_len: c_int,
) -> c_int {
    // 判断当系统是否具备 btf 文件生成的条件
    if PathBuf::from(VMLINUX_BTF_PATH).exists() {
        return 0;
    }

    // 创建指向原始内存的切片，在原始内存上进行安全有效的操作（slice）
    let tar_bytes = unsafe { slice::from_raw_parts(tar_bin, tar_len as usize) };
    let decompressed_bytes = {
        let mut val = vec![];
        // 从给定的读取器创建一个新的解码器，立即解析gzip 的 header 信息
        let mut gzip_reader = GzDecoder::new(tar_bytes);
        // read_to_end 方法读取所有的字节，直到 EOF 标识，并将他们放入缓冲区
        if let Err(e) = gzip_reader.read_to_end(&mut val) {
            eprintln!("Failed to decompress: {}", e);
            return -EINVAL;
        }
        val
    };

    // new() 创建一个新的存档，并将底层对象作为读取器
    let mut tar = Archive::new(&decompressed_bytes[..]);
    // 捕获当前系统信息，生成与 min_core_btf.tar.o 中 btf 存档路径相同的路径字符串
    // 最终效果：./btfhub-archive/ubuntu/20.04/x86_64/5.4.0-40-generic.btf
    let local_btf_path =
        PathBuf::from("./btfhub-archive").join(match generate_current_system_btf_archive_path() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to generate running kernel btf path: {:?}", e);
                return -ENOENT;
            }
        });
    // 针对 Archive 存档的条目，构建一个迭代器
    // 迭代器中的每一个条目必须按照顺序处理，否则读取的每个条目的内容可能被破坏
    let entries = match tar.entries() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to read entries in the tar: {}", e);
            return -EINVAL;
        }
    };
    let mut btf_path = None;
    for entry in entries {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to read entry: {}", e);
                return -EIO;
            }
        };
        // path of a entry looks like `./btfhub-archive/ubuntu/20.04/x86_64/5.4.0-40-generic.btf`
        // entry.header() 返回归档条目的头部信息，提供了对归档条目元数据的访问
        // entry.header().path() 返回存储在头部信息中原始的路径名，如果路径名不是 unicode 编码或者在 windows 平台上，将不可用。该方法将会转 \ 字符为目录分割符
        let path = match entry.header().path() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to read path name: {}", e);
                return -EILSEQ;
            }
        };

        // 根据当前系统生成的 BTF 存档路径信息 同 btfhub-archive 存档的 btf 文件地址比对，检索出使用与当前系统的 btf 文件
        if path == local_btf_path {
            let mut temp_file = match mkstemp::TempFile::new("/tmp/eunomia.btf.XXXXXX", false) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Failed to create a tempfile to store the btf: {}", e);
                    return -EIO;
                }
            };
            // 返回归档条目文件开始的位置，以字节为单位
            // 如果条目文件是连续的，且底层读写器实现了 Seek，则从 header_pos 到 header_pos + 512 的字节包含头部信息
            // 此处是将该条目拷贝到 file_bytes 缓冲区
            let file_bytes = &decompressed_bytes[entry.raw_file_position() as usize
                ..(entry.raw_file_position() + entry.size()) as usize];
            // 将 btf 文件保存到临时文件
            if let Err(e) = temp_file.write_all(file_bytes) {
                eprintln!("Failed to write btf things to the tempfile: {}", e);
                return -EIO;
            }
            btf_path = Some(temp_file.path().to_string());
        }
    }

    // 获取btf文件的地址
    let btf_path = match btf_path {
        Some(v) => v,
        None => {
            eprintln!("Failed to find the btf archive matching the running kernel");
            return -ENOENT;
        }
    };
    let btf_path_bytes = btf_path.as_bytes();
    // The buffer will be passed to C program, so allocate it with malloc
    // 缓冲区将传递个C程序，所有用 malloc 初始化了一个内存空间。
    let holder = unsafe { malloc(btf_path_bytes.len() + 1) } as *mut u8;
    if holder.is_null() {
        eprintln!("Unable to allocate a buffer for c string");
        return -ENOMEM;
    }
    // 将 holder 封装成一个安全的内存切片
    let holder_slice = unsafe { slice::from_raw_parts_mut(holder, btf_path_bytes.len() + 1) };
    // 将 btf 文件的路径信息以切片的方式拷贝到 holder_slice 中
    holder_slice[..btf_path_bytes.len()].copy_from_slice(btf_path_bytes);
    // C-Strings require a trailing zero
    // C 字符创的最后一个字符是以 0 结尾的
    holder_slice[btf_path_bytes.len()] = 0;
    // 完成了 btf 文件信息赋值给 path 指针
    *unsafe { &mut *path } = holder as *const c_char;
    0
}

extern "C" {
    static _binary_min_core_btfs_tar_gz_start: c_char;
    static _binary_min_core_btfs_tar_gz_end: c_char;
}

///
#[no_mangle]
pub extern "C" fn ensure_core_btf_with_linked_tar(path: *mut *const c_char) -> c_int {
    /*
        通过 bpftool gen min_core_btf 命令，根据 epbf 生成的.o 目标文件，生成 btfhub-archive
        归档的所有厂商 btf 的精简 btf，将所有的 btf 文件打包成 min_core_btfs.tar.gz

        ld -r -b binary min_core_btfs.tar.gz -o min_core_btfs_tar.o 生成的静态链接文件 .o

        最终通过 clang <your_program> libbpf_compatible.a min_core_btf.tar.o 生成可执行的
        二进制文件，其中 min_core_btf.tar.o 链接中定义了 _binary_min_core_btfs_tar_gz_end
        和 _binary_min_core_btfs_tar_gz_start 为嵌入的 tar.gz 文件的范围。
    */
    let len = unsafe {
        &_binary_min_core_btfs_tar_gz_end as *const c_char as usize
            - &_binary_min_core_btfs_tar_gz_start as *const c_char as usize
    };
    ensure_core_btf_with_tar_binary(
        path,
        unsafe { &_binary_min_core_btfs_tar_gz_start as *const c_char } as *const u8,
        len as c_int,
    )
}

#[no_mangle]
pub extern "C" fn clean_core_btf_rs(path: *mut c_char) {
    if path.is_null() {
        return;
    }
    let path_buf = PathBuf::from(
        unsafe { CStr::from_ptr(path) }
            .to_string_lossy()
            .to_string(),
    );
    if let Err(e) = std::fs::remove_file(path_buf) {
        eprintln!("Failed to perform clean: {}", e);
    }
    unsafe { libc::free(path as *mut c_void) };
}
