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
#ifndef _CPLPLATE_ATOMIC_H
#define _CPLPLATE_ATOMIC_H

typedef struct { int v; } atomic_t;

typedef struct { long v; } atomic_long_t;

#define ATOMIC_INIT(__n) { (__n) }

static inline long atomic_long_read(const atomic_long_t *ptr)
{
	return ptr->v;
}

static inline void atomic_long_set(atomic_long_t *ptr, long v)
{
	ptr->v = v;
}

static inline int atomic_read(const atomic_t *ptr)
{
	return ptr->v;
}

static inline void atomic_set(atomic_t *ptr, long v)
{
	ptr->v = v;
}

#ifndef atomic_cmpxchg
#define atomic_cmpxchg(__ptr, __old, __new)  \
	__sync_val_compare_and_swap(&(__ptr)->v, __old, __new)
#endif

#ifndef atomic_sub_fetch
#define atomic_sub_fetch(__ptr, __n)	\
	__sync_sub_and_fetch(&(__ptr)->v, __n)
#endif

#ifndef atomic_add_fetch
#define atomic_add_fetch(__ptr, __n)	\
	__sync_add_and_fetch(&(__ptr)->v, __n)
#endif

#ifdef CONFIG_SMP
#ifndef smp_mb
#define smp_mb()	__sync_synchronize()
#endif
#ifndef smp_rmb
#define smp_rmb()	smp_mb()
#endif
#ifndef smp_wmb
#define smp_wmb()	smp_mb()
#endif
#else  /* !CONFIG_SMP */
#define smp_mb()	do { } while (0)
#define smp_rmb()	do { } while (0)
#define smp_wmb()	do { } while (0)
#endif /* !CONFIG_SMP */

#define ACCESS_ONCE(x) (*(volatile __typeof__(x) *)&(x))

#define compiler_barrier()	__asm__ __volatile__("": : :"memory")

#ifndef cpu_relax
#define cpu_relax() __sync_synchronize()
#endif

#endif // _CPLPLATE_ATOMIC_H