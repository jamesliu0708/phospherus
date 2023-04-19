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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include "cplplate/ancillaries.h"
#include "cplplate/signal.h"

static void __printout(const char *name, const char *header,
			  const char *fmt, va_list ap)
{
	FILE *fp = stderr;

	if (header)
		fputs(header, fp);

	fprintf(fp, "[%s] ", name ?: "main");
	vfprintf(fp, fmt, ap);
	fputc('\n', fp);
	fflush(fp);
}

void ___panic(const char *fn, const char *name,
	     const char *fmt, va_list ap)
{
	char *p;

	if (vsprintf(&p, "BUG in %s(): ", fn) < 0)
		p = "BUG: ";
	__printout(name, p, fmt, ap);
	exit(1);
}


void __early_panic(const char *fn, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	___panic(fn, NULL, fmt, ap);
	va_end(ap);
}

