/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
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

#ifndef __ISCSI_USR_DISC_H__
#define __ISCSI_USR_DISC_H__

#include <stdint.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"
#include "libopeniscsiusr/libopeniscsiusr_discovery.h"
#include "idbm.h"

struct iscsi_discovery_cfg {
	enum iscsi_discovery_type type;
	char address[NI_MAXHOST];
	int32_t port;
	enum iscsi_startup_type startup;
	int32_t iscsid_req_tmo;
	union {
		struct iscsi_sendtargets_config sendtargets;
		struct iscsi_isns_config isns;
	} u;
};

#endif /* End of __ISCSI_USR_DISC_H__ */
