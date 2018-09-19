/*
 * Copyright (C) 2017 Red Hat, Inc.
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

#ifndef _LIB_OPEN_ISCSI_USR_DISCOVERY_H_
#define _LIB_OPEN_ISCSI_USR_DISCOVERY_H_

#include <stdint.h>
#include <stdbool.h>

#include "libopeniscsiusr_common.h"

// TODO(Gris Ge): We should only expose LIBISCSI_DISCOVERY_TYPE_SENDTARGETS,
//                and LIBISCSI_DISCOVERY_TYPE_ISNS, rest are internal use only.

enum iscsi_discovery_type {
	LIBISCSI_DISCOVERY_TYPE_SENDTARGETS = 0,
	LIBISCSI_DISCOVERY_TYPE_ISNS = 1,
	LIBISCSI_DISCOVERY_TYPE_OFFLOAD_SENDTARGETS = 2,
//	LIBISCSI_DISCOVERY_TYPE_SLP = 3,		// Not supported yet
	LIBISCSI_DISCOVERY_TYPE_STATIC = 4,
	LIBISCSI_DISCOVERY_TYPE_FW = 5,
};

struct __DLL_EXPORT iscsi_discovery_cfg;

#endif /* End of _LIB_OPEN_ISCSI_USR_DISCOVERY_H_ */
