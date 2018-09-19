/*
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#ifndef __ISCSI_USR_ISCSID_H__
#define __ISCSI_USR_ISCSID_H__

#include <linux/limits.h>		// For PATH_MAX
#include <stdint.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"
#include "idbm.h"
#include "node.h"
#include "disc.h"

struct iscsid_cfg {
	char startup[VALUE_MAXVAL];
	bool safe_logout;
	char config_file[PATH_MAX];
	struct iscsi_node node;
	struct iscsi_sendtargets_config st;
	struct iscsi_isns_config isns;
};

__DLL_LOCAL int _iscsid_cfg_load(struct iscsi_context *ctx,
				 struct iscsid_cfg **d_cfg);

__DLL_LOCAL void _iscsid_cfg_free(struct iscsid_cfg *d_cfg);

__DLL_LOCAL int _iscsid_send_target(struct iscsi_context *ctx,
				    struct iscsi_discovery_cfg *cfg,
				    uint32_t host_no);

#endif /* End of __ISCSI_USR_ISCSID_H__ */
