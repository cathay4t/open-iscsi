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

#ifndef __ISCSI_OPEN_USR_IDBM_H__
#define __ISCSI_OPEN_USR_IDBM_H__

#include <stdio.h>
#include <stdbool.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"

struct __DLL_LOCAL idbm;

__DLL_LOCAL int _idbm_lock(struct iscsi_context *ctx);
__DLL_LOCAL void _idbm_unlock(struct iscsi_context *ctx);
__DLL_LOCAL int _idbm_print_iface(struct iscsi_context *ctx,
				  struct iscsi_iface *iface, FILE *f);

#endif /* End of __ISCSI_OPEN_USR_IDBM_H__ */
