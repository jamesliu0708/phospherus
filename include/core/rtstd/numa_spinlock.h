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

// Date: Wed Apr 24 14:09:02 CST 2023
#ifndef _RDSTD_NUMA_SPINLOCK_H
#define _RDSTD_NUMA_SPINLOCK_H

#include <features.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* The NUMA spinlock.  */
struct numa_spinlock;

/* The NUMA spinlock information for each thread.  */
struct numa_spinlock_info
{
    /* The workload function of this thread.  */
    void *(*workload) (void *);
    /* The argument pointer passed to the workload function.  */
    void *argument;
    /* The return value of the workload function.  */
    void *result;
    /* The pointer to the NUMA spinlock.  */
    struct numa_spinlock *lock;
    /* The next thread on the local NUMA spinlock thread list.  */
    struct numa_spinlock_info *next;
    /* The NUMA node number.  */
    unsigned int node;
    /* Non-zero to indicate that the thread wants the NUMA spinlock.  */
    int pending;
    /* Reserved for future use.  */
    void *__reserved[4];
};

/* Return a pointer to a newly allocated NUMA spinlock.  */
extern struct numa_spinlock *numa_spinlock_alloc (void);

/* Free the memory space of the NUMA spinlock.  */
extern void numa_spinlock_free (struct numa_spinlock *);

/* Initialize the NUMA spinlock information block.  */
extern int numa_spinlock_init (struct numa_spinlock *,
			       struct numa_spinlock_info *);

/* Apply and wait for the NUMA spinlock with a NUMA spinlock information
   block.  */
extern void numa_spinlock_apply (struct numa_spinlock_info *);

/* Apply for the non-blocking NUMA spinlock with a NUMA spinlock
   information block.  */
extern void numa_spinlock_apply_nonblock (struct numa_spinlock_info *);

/* Non-zero if the NUMA spinlock is pending.  */
extern int numa_spinlock_pending (struct numa_spinlock_info *);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // _RDSTD_NUMA_SPINLOCK_H
