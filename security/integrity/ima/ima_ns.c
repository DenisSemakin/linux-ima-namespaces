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

#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/ima.h>

#include "ima.h"

static void destroy_ima_ns(struct ima_namespace *ns);

static struct ucounts *inc_ima_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_IMA_NAMESPACES);
}

static void dec_ima_namespaces(struct ucounts *ucounts)
{
	return dec_ucount(ucounts, UCOUNT_IMA_NAMESPACES);
}

/**
 * Clone a new ns copying an original ima namespace, setting refcount to 1
 *
 * @user_ns: user namespace that current task runs in
 * @old_ns: old ima namespace to clone
 * Return ERR_PTR(-ENOMEM) on error (failure to kmalloc), new ns otherwise
 */
static struct ima_namespace *create_ima_ns(struct user_namespace *user_ns,
					   struct ima_namespace *old_ns)
{
	struct ima_namespace *ns;
	struct ucounts *ucounts;
	int err;

	err = -ENOSPC;
	ucounts = inc_ima_namespaces(user_ns);
	if (!ucounts)
		goto fail;

	err = -ENOMEM;
	ns = kmalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns)
		goto fail_dec;

	err = ima_init_namespace(ns);
	if (err)
		goto fail_free;

	kref_init(&ns->kref);
	ns->ns.ops = &imans_operations;
	ns->parent = get_ima_ns(old_ns);
	ns->user_ns = get_user_ns(user_ns);
	ns->ucounts = ucounts;

	memset(&ns->sfs, 0, sizeof(ns->sfs));
	err = ima_ns_fs_init(ns, old_ns->sfs.dentry[IMAFS_DENTRY_NAMESPACES]);
	if (err)
		goto fail_destroy_ima_ns;

	return ns;

fail_destroy_ima_ns:
	destroy_ima_ns(ns);
	goto fail;

fail_free:
	kfree(ns);
fail_dec:
	dec_ima_namespaces(ucounts);
fail:
	return ERR_PTR(err);
}

/**
 * Copy task's ima namespace, or clone it if flags specifies CLONE_NEWNS.
 *
 * @bool: whether to copy or just get a reference to it
 * @user_ns: user namespace that current task runs in
 * @old_ns: old ima namespace to clone
 */

struct ima_namespace *copy_ima_ns(bool copy,
				  struct user_namespace *user_ns,
				  struct ima_namespace *old_ns)
{
	struct ima_namespace *new_ns;

	get_ima_ns(old_ns);
	if (!copy)
		return old_ns;

	new_ns = create_ima_ns(user_ns, old_ns);
	put_ima_ns(old_ns);

	return new_ns;
}

static void destroy_ima_ns(struct ima_namespace *ns)
{
	put_ima_ns(ns->parent);
	put_user_ns(ns->user_ns);
	ns_free_inum(&ns->ns);
	dec_ima_namespaces(ns->ucounts);
	free_ns_status_cache(ns);
	ima_free_queue_entries(ns);
	ima_ns_fs_free(ns);
	kfree(ns);
}

void free_ima_ns(struct kref *kref)
{
	struct ima_namespace *ns;

	ns = container_of(kref, struct ima_namespace, kref);

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

static struct ns_common *imans_get(struct task_struct *task)
{
	struct ima_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->ima_ns;
		get_ima_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static void imans_put(struct ns_common *ns)
{
	put_ima_ns(to_ima_ns(ns));
}

static int imans_install(struct nsproxy *nsproxy, struct ns_common *new)
{
	struct ima_namespace *ns = to_ima_ns(new);

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	put_ima_ns(nsproxy->ima_ns);
	nsproxy->ima_ns = get_ima_ns(ns);

	return 0;
}

static struct user_namespace *imans_owner(struct ns_common *ns)
{
	return to_ima_ns(ns)->user_ns;
}

const struct proc_ns_operations imans_operations = {
	.name = "ima",
	.get = imans_get,
	.put = imans_put,
	.install = imans_install,
	.owner = imans_owner,
};
