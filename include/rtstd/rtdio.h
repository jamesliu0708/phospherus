// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Date: Wed Apr 15 18:47:15 CST 2023
#pragma GCC system_header

#ifndef _RDSTD_RTDIO_H
#define _RDSTD_RTDIO_H
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void rtstd_print_init(void);

int rt_vfprintf(FILE *stream, const char *format, va_list args);

int rt_vprintf(const char *format, va_list args);

int rt_fprintf(FILE *stream, const char *format, ...);

int rt_printf(const char *format, ...);

int rt_puts(const char *s);

int rt_fputs(const char *s, FILE *stream);

int rt_fputc(int c, FILE *stream);

int rt_putchar(int c);

size_t rt_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

void rt_syslog(int priority, const char *format, ...);

void rt_vsyslog(int priority, const char *format, va_list args);

int rt_print_init(size_t buffer_size, const char *name);

const char *rt_print_buffer_name(void);

void rt_print_flush_buffers(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // _RDSTD_RTDIO_H