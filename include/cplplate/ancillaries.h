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
#ifndef _CPLPLATE_ANCILLARIES_H
#define _CPLPLATE_ANCILLARIES_H
#include <stdarg.h>
#include <cplplate/compiler.h>

#define early_panic(__fmt, __args...)		\
	__early_panic(__func__, __fmt, ##__args)

#ifdef __cplusplus
extern "C" {
#endif

void __noreturn __early_panic(const char *fn,
			      const char *fmt, ...);

void __noreturn ___panic(const char *fn,
			 const char *name,
			 const char *fmt, va_list ap);

void __noreturn __panic(const char *fn,
			const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif //_CPLPLATE_ANCILLARIES_H