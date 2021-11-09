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
	struct ima_namespace *ima_ns;
	int err;

	ima_ns = kmem_cache_zalloc(imans_cachep, GFP_KERNEL);
	if (!ima_ns)
		return ERR_PTR(-ENOMEM);
	printk(KERN_INFO "NEW     ima_ns: %p\n", ima_ns);

	kref_init(&ima_ns->kref);

	err = ns_alloc_inum(&ima_ns->ns);
	if (err)
		goto fail_free;
	ima_ns->ns.ops = &imans_operations;

	return ima_ns;

fail_free:
	kmem_cache_free(imans_cachep, ima_ns);

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
	struct ima_namespace *ima_ns;

	ima_ns = create_ima_ns();
	if (IS_ERR(ima_ns))
		return ima_ns;

	ima_ns->user_ns = user_ns;

	ima_init_namespace(ima_ns);

	return ima_ns;
}

static void destroy_ima_ns(struct ima_namespace *ima_ns)
{
	printk(KERN_INFO "DESTROY ima_ns: %p\n", ima_ns);
	ns_free_inum(&ima_ns->ns);
	kmem_cache_free(imans_cachep, ima_ns);
}

void free_ima_ns(struct kref *kref)
{
	struct ima_namespace *ns;

	ns = container_of(kref, struct ima_namespace, kref);
	BUG_ON(ns == &init_ima_ns);

	destroy_ima_ns(ns);
}

static struct ns_common *imans_get(struct task_struct *task)
{
	struct user_namespace *user_ns;
	struct ima_namespace *ima_ns;

	rcu_read_lock();
	user_ns = __task_cred(task)->user_ns;
	rcu_read_unlock();

	ima_ns = get_ima_ns(&user_ns->ima_ns->ns);

	return &ima_ns->ns;
}

static struct ns_common *imans_for_children_get(struct task_struct *task)
{
	struct user_namespace *user_ns;
	struct ima_namespace *ima_ns;

	rcu_read_lock();
	user_ns = __task_cred(task)->user_ns;
	rcu_read_unlock();

	ima_ns = get_ima_ns(&user_ns->ima_ns_for_children->ns);

	return &ima_ns->ns;
}

static void imans_put(struct ns_common *ns)
{
	put_ima_ns(&to_ima_ns(ns)->ns);
}

static int imans_install(struct nsset *nsset, struct ns_common *ns)
{
	struct user_namespace *user_ns = nsset->cred->user_ns;

	printk(KERN_INFO "%s CALLED!\n", __func__);

	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	put_ima_ns(&user_ns->ima_ns->ns);
	user_ns->ima_ns = get_ima_ns(ns);

	put_ima_ns(&user_ns->ima_ns_for_children->ns);
	user_ns->ima_ns_for_children = get_ima_ns(ns);

	return 0;
}

static struct user_namespace *imans_owner(struct ns_common *ns)
{
	return to_ima_ns(ns)->user_ns;
}

const struct proc_ns_operations imans_operations = {
	.name = "ima",
	.type = CLONE_NEWUSER,
	.get = imans_get,
	.put = imans_put,
	.install = imans_install,
	.owner = imans_owner,
};

const struct proc_ns_operations imans_for_children_operations = {
	.name = "ima_for_children",
	.type = CLONE_NEWUSER,
	.get = imans_for_children_get,
	.put = imans_put,
	.install = imans_install,
	.owner = imans_owner,
};

int __init imans_cache_init(void)
{
	imans_cachep = KMEM_CACHE(ima_namespace, SLAB_PANIC);
	return 0;
}
subsys_initcall(imans_cache_init)
