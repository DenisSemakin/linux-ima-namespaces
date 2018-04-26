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
#include <linux/ima.h>

#include "ima.h"

void free_ns_status_cache(struct ima_namespace *ns)
{
	struct ns_status *status, *next;

	write_lock(&ns->ns_status_lock);
	rbtree_postorder_for_each_entry_safe(status, next,
					     &ns->ns_status_tree, rb_node) {
		write_lock(&status->iint->ns_list_lock);

		if (!list_empty(&status->ns_next)) {
			list_del(&status->ns_next);
			INIT_LIST_HEAD(&status->ns_next);
		}

		write_unlock(&status->iint->ns_list_lock);

		iint_put(status->iint);

		kmem_cache_free(ns->ns_status_cache, status);
		printk(KERN_INFO "free status: %p; ns : %p\n", status, ns);
	}
	ns->ns_status_tree = RB_ROOT;
	write_unlock(&ns->ns_status_lock);
	kmem_cache_destroy(ns->ns_status_cache);
}

/*
 * ns_status_off_list_free: a list of items that is NOT connected to the
 *                          iint's list anymore is to be freed
 */
void ns_status_off_list_free(struct list_head *head)
{
	struct ns_status *curr, *next;

	list_for_each_entry_safe(curr, next, head, ns_next) {
		list_del_init(&curr->ns_next);

		iint_put(curr->iint);

		write_lock(&curr->ns->ns_status_lock);

		rb_erase(&curr->rb_node, &curr->ns->ns_status_tree);
		RB_CLEAR_NODE(&curr->rb_node);

		write_unlock(&curr->ns->ns_status_lock);

		ns_status_put(curr);
	}
}

/*
 * __ima_ns_status_find - return the ns_status associated with an inode
 *                        since this function is called with the writer
 *                        lock held, we can clean up unused ns_status we
 *                        find
 */
static struct ns_status *__ima_ns_status_find(struct ima_namespace *ns,
					      struct inode *inode)
{
	struct ns_status *status;
	struct rb_node *n = ns->ns_status_tree.rb_node;

	while (n) {
		status = rb_entry(n, struct ns_status, rb_node);

		if (inode < status->inode)
			n = n->rb_left;
		else if (inode > status->inode)
			n = n->rb_right;
		else
			break;
	}
	if (!n)
		return NULL;

	return status;
}

void insert_ns_status(struct ima_namespace *ns, struct inode *inode,
		      struct ns_status *status)
{
	struct rb_node **p;
	struct rb_node *node, *parent = NULL;
	struct ns_status *test_status;

	p = &ns->ns_status_tree.rb_node;
	while (*p) {
		parent = *p;
		test_status = rb_entry(parent, struct ns_status, rb_node);
		if (inode < test_status->inode)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	node = &status->rb_node;
	rb_link_node(node, parent, p);
	rb_insert_color(node, &ns->ns_status_tree);
}

void ns_status_free(struct kref *ref)
{
	struct ns_status *status = container_of(ref, struct ns_status, ref);

	kmem_cache_free(status->ns->ns_status_cache, status);
}

static void ima_ns_status_unlink(struct ima_namespace *ns,
				 struct ns_status *status)
{
	write_lock(&status->iint->ns_list_lock);

	if (!list_empty(&status->ns_next))
		list_del_init(&status->ns_next);
	write_unlock(&status->iint->ns_list_lock);

	iint_put(status->iint);

	rb_erase(&status->rb_node, &ns->ns_status_tree);
	RB_CLEAR_NODE(&status->rb_node);
}

struct ns_status *ima_get_ns_status(struct ima_namespace *ns,
				    struct inode *inode,
				    struct integrity_iint_cache *iint)
{
	struct ns_status *status;
	int skip_insert = 0;

	/* prevent anyone from finding the status since we may free it */
	write_lock(&ns->ns_status_lock);

	status = ns_status_get(__ima_ns_status_find(ns, inode));

	if (status) {
		BUG_ON(status->inode != inode);
		/*
		 * Unlike integrity_iint_cache we are not free'ing the
		 * ns_status data when the inode is free'd. So, in addition to
		 * checking the inode pointer, we need to make sure the
		 * (i_generation, i_ino) pair matches as well. In the future
		 * we might want to add support for lazily walking the rbtree
		 * to clean it up.
		 */
		if (status->iint != iint) {
			ima_ns_status_unlink(ns, status);
			/* put reference from above */
			ns_status_put(status);
			/* free it */
			ns_status_put(status);
			goto get_new;
		} else if (inode->i_ino == status->i_ino &&
			   inode->i_generation == status->i_generation) {
			write_unlock(&ns->ns_status_lock);
			return status;
		}

		/* Same inode number is reused, overwrite the ns_status */
		skip_insert = 1;
	} else {
get_new:
		write_unlock(&ns->ns_status_lock);

		status = kmem_cache_alloc(ns->ns_status_cache, GFP_NOFS);
		if (!status)
			return ERR_PTR(-ENOMEM);

		kref_init(&status->ref);
		ns_status_get(status);
		INIT_LIST_HEAD(&status->ns_next);

		printk(KERN_INFO "new status: %p, ns: %p\n", status, ns);

		write_lock(&ns->ns_status_lock);
	}

	if (!skip_insert) {
		insert_ns_status(ns, inode, status);
		status->iint = iint_get(iint);
	}

	status->inode = inode;
	status->i_ino = inode->i_ino;
	status->i_generation = inode->i_generation;
	status->flags = 0UL;
	status->ns = ns;
	status->measured_pcrs = 0;
	status->ima_file_status = INTEGRITY_UNKNOWN;
	status->ima_mmap_status = INTEGRITY_UNKNOWN;
	status->ima_bprm_status = INTEGRITY_UNKNOWN;
	status->ima_read_status = INTEGRITY_UNKNOWN;
	status->ima_creds_status = INTEGRITY_UNKNOWN;

	write_lock(&iint->ns_list_lock);
	if (list_empty(&status->ns_next))
		list_add_tail(&status->ns_next, &iint->ns_list);
	write_unlock(&iint->ns_list_lock);

	write_unlock(&ns->ns_status_lock);

	return status;
}
