/*
 * Copyright (C) 2018 IBM Corporation
 * Author:
 *  Yuqiong Sun <suny@us.ibm.com>
 *  Stefan Berger <stefanb@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/ima.h>

#include "ima.h"

void ima_iint_clear_ns_list(struct integrity_iint_cache *iint)
{
	struct ns_status *curr, *next;

	write_lock(&iint->ns_list_lock);

	list_for_each_entry_safe(curr, next, &iint->ns_list, ns_next)
		ima_ns_status_list_del(curr);

	write_unlock(&iint->ns_list_lock);
}

