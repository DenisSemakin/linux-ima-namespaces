/*
 * Copyright (C) 2016-2018 IBM Corporation
 * Author:
 *   Yuqiong Sun <suny@us.ibm.com>
 *   Stefan Berger <stefanb@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/export.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/ima.h>
#include <linux/slab.h>

#include "ima.h"

int ima_init_namespace(struct ima_namespace *ns)
{
	int ret = 0;

	ns->ns_status_tree = RB_ROOT;
	rwlock_init(&ns->ns_status_lock);
	ns->ns_status_cache = KMEM_CACHE(ns_status, SLAB_PANIC);
	if (!ns->ns_status_cache)
		return -ENOMEM;

#ifdef CONFIG_IMA_NS
	ns->ns.ops = &imans_operations;
	ret = ns_alloc_inum(&ns->ns);
	if (ret)
		kmem_cache_destroy(ns->ns_status_cache);
#endif
	init_rwsem(&ns->tpm_chip_lock);
	if (ns != &init_ima_ns)
		ns->tpm_chip = NULL;

	return ret;
}

int __init ima_ns_init(void)
{
	return ima_init_namespace(&init_ima_ns);
}

struct ima_namespace init_ima_ns = {
	.kref = KREF_INIT(1),
	.user_ns = &init_user_ns,
	.ucounts = NULL,
	.parent = NULL,
};
EXPORT_SYMBOL(init_ima_ns);
