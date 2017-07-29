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
	size_t i;

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
	ns->extended_pcr = false;
	ns->tpm_provider = NULL;

	INIT_LIST_HEAD(&ns->ima_measurements);
	atomic_long_set(&ns->ima_htable.len, 0);
	atomic_long_set(&ns->ima_htable.violations, 0);

	for (i = 0; i < IMA_MEASURE_HTABLE_SIZE; i++)
		INIT_HLIST_HEAD(&ns->ima_htable.queue[i]);

	INIT_LIST_HEAD(&ns->ima_policy_rules);
	INIT_LIST_HEAD(&ns->ima_temp_rules);
	INIT_LIST_HEAD(&ns->iint_list);
	ns->ima_rules = &ima_default_rules;
	ima_update_policy_flag(ns);

	ns->valid_policy = 1;

	return ret;
}

int __init ima_ns_init(void)
{
	int err;

	err = ima_init_namespace(&init_ima_ns);
	if (err)
		return err;

	return ima_ns_fs_init(&init_ima_ns, NULL);
}

struct ima_namespace init_ima_ns = {
	.kref = KREF_INIT(1),
	.user_ns = &init_user_ns,
	.ucounts = NULL,
	.parent = NULL,
	.ima_measurements = LIST_HEAD_INIT(init_ima_ns.ima_measurements),
};
EXPORT_SYMBOL(init_ima_ns);
