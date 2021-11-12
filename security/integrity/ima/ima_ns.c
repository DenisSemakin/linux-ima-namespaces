// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016-2018 IBM Corporation
 * Author:
 *  Yuqiong Sun <suny@us.ibm.com>
 *  Stefan Berger <stefanb@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/ima.h>
#include <linux/mount.h>
#include <linux/proc_ns.h>
#include <linux/lsm_hooks.h>

#include "ima.h"

static struct kmem_cache *imans_cachep;

static struct ima_namespace *create_ima_ns(void)
{
	struct ima_namespace *ns;
	int err;

	ns = kmem_cache_zalloc(imans_cachep, GFP_KERNEL);
	if (!ns)
		return ERR_PTR(-ENOMEM);
	printk(KERN_INFO "NEW     ima_ns: %p\n", ns);

	kref_init(&ns->kref);

	err = ima_init_namespace(ns);
	if (err)
		goto fail_free;

#ifdef CONFIG_IMA_QUEUE_EARLY_BOOT_KEYS
	ns->ima_process_keys = false;
	mutex_init(&ns->ima_keys_lock);
	INIT_LIST_HEAD(&ns->ima_keys);
#endif

	return ns;

fail_free:
	kmem_cache_free(imans_cachep, ns);

	return ERR_PTR(err);
}

/**
 * Copy an ima namespace
 *
 * @old_ns: old ima namespace to clone
 * @user_ns: User namespace
 */
struct ima_namespace *copy_ima_ns(struct ima_namespace *old_ns,
				  struct user_namespace *user_ns)
{
	struct ima_namespace *new_ns;

	new_ns = create_ima_ns();
	if (IS_ERR(new_ns))
		return new_ns;

	new_ns->user_ns = user_ns;

	return new_ns;
}

static void destroy_ima_ns(struct ima_namespace *ns)
{
	printk(KERN_INFO "DESTROY ima_ns: %p\n", ns);
	free_ns_status_cache(ns);
	kmem_cache_free(imans_cachep, ns);
}

void free_ima_ns(struct kref *kref)
{
	struct ima_namespace *ns;

	ns = container_of(kref, struct ima_namespace, kref);
	BUG_ON(ns == &init_ima_ns);

	destroy_ima_ns(ns);
}

unsigned long iint_flags(struct integrity_iint_cache *iint,
			 struct ns_status *status)
{
	if (!status)
		return iint->flags;

	return (iint->flags & ~IMA_NS_STATUS_FLAGS) |
	       (status->flags & IMA_NS_STATUS_FLAGS);
}

unsigned long set_iint_flags(struct integrity_iint_cache *iint,
			     struct ns_status *status, unsigned long flags)
{
	iint->flags = flags;
	if (status)
		status->flags = flags & IMA_NS_STATUS_FLAGS;

	return flags;
}

int __init imans_cache_init(void)
{
	imans_cachep = KMEM_CACHE(ima_namespace, SLAB_PANIC);
	return 0;
}
subsys_initcall(imans_cache_init)
