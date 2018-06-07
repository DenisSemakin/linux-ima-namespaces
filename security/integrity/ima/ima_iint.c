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
	LIST_HEAD(list);

	write_lock(&iint->ns_list_lock);
	list_replace(&iint->ns_list, &list);
	write_unlock(&iint->ns_list_lock);

	ns_status_off_list_free(&list);
}

