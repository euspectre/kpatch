/*
 * kpatch.h
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * Contains the API for the core kpatch module used by the patch modules
 */

#ifndef _KPATCH_H_
#define _KPATCH_H_

#include <linux/types.h>
#include <linux/module.h>

enum kpatch_op {
	KPATCH_OP_NONE,
	KPATCH_OP_PATCH,
	KPATCH_OP_UNPATCH,
};

struct kpatch_func {
	/* public */
	unsigned long new_addr;
	unsigned long new_size;
	unsigned long old_addr;
	unsigned long old_size;
	unsigned long sympos;
	const char *name;
	struct list_head list;
	int force;

	/* private */
	struct hlist_node node;
	enum kpatch_op op;
	struct kobject kobj;
};

struct kpatch_dynrela {
	unsigned long dest;
	unsigned long src;
	unsigned long type;
	unsigned long sympos;
	const char *name;
	int addend;
	int external;
	struct list_head list;
};

struct kpatch_hook {
	struct list_head list;
	void (*hook)(void);
};

struct kpatch_object {
	struct list_head list;
	const char *name;
	struct list_head funcs;
	struct list_head dynrelas;
	struct list_head hooks_load;
	struct list_head hooks_unload;

	/* private */
	struct module *mod;
	struct kobject kobj;
};

struct kpatch_module {
	/* public */
	struct module *mod;
	struct list_head objects;

	/* public read-only */
	bool enabled;

	/* private */
	struct list_head list;
	struct kobject kobj;
};

extern struct kobject *kpatch_root_kobj;

extern int kpatch_register(struct kpatch_module *kpmod, bool replace);
extern int kpatch_unregister(struct kpatch_module *kpmod);

/*
 * A destructor function of this type can be provided when freeing the
 * shadow variables.
 *
 * 'obj' - the object the shadow variable is attached to;
 * 'shadow_data' - the data contained in the shadow_variable, as
 *   kpatch_shadow_get() would return.
 *
 * Be careful not to call any new or patched kernel functions from the dtor
 * if these functions use shadow variables themselves. The dtor may be
 * called under the same lock as kpatch_shadow_*() functions use to operate
 * on the shadow variables. Deadlocks are possible in such situations.
 *
 * It is up to the caller of kpatch_shadow_free*() to make sure the shadow
 * variables cannot be accessed after they have been freed or in parallel to
 * freeing.
 */
typedef void (*kpatch_shadow_dtor_t)(void *obj, void *shadow_data);

extern void *kpatch_shadow_alloc(void *obj, char *var, size_t size, gfp_t gfp);
extern void kpatch_shadow_free(void *obj, char *var);
extern void kpatch_shadow_free_with_dtor(void *obj, char *var,
					 kpatch_shadow_dtor_t dtor);
extern void kpatch_shadow_free_all(char *var, kpatch_shadow_dtor_t dtor);
extern void *kpatch_shadow_get(void *obj, char *var);

#endif /* _KPATCH_H_ */
