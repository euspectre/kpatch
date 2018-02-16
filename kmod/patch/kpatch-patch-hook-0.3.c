/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include "kpatch.h"
#include "kpatch-patch.h"

static bool replace;
module_param(replace, bool, S_IRUGO);
MODULE_PARM_DESC(replace, "replace all previously loaded patch modules");

extern struct kpatch_patch_func __kpatch_funcs[], __kpatch_funcs_end[];
extern struct kpatch_patch_dynrela __kpatch_dynrelas[], __kpatch_dynrelas_end[];
extern struct kpatch_patch_hook __kpatch_hooks_load[], __kpatch_hooks_load_end[];
extern struct kpatch_patch_hook __kpatch_hooks_unload[], __kpatch_hooks_unload_end[];
extern unsigned long __kpatch_force_funcs[], __kpatch_force_funcs_end[];
extern char __kpatch_checksum[];

static struct kpatch_module kpmod;
static struct kobject *patch_kobj;

static ssize_t patch_enabled_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", kpmod.enabled);
}

static ssize_t patch_enabled_store(struct kobject *kobj,
				   struct kobj_attribute *attr, const char *buf,
				   size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	val = !!val;

	if (val)
		ret = kpatch_register(&kpmod, replace);
	else
		ret = kpatch_unregister(&kpmod);

	if (ret)
		return ret;

	return count;
}

static ssize_t patch_checksum_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", __kpatch_checksum);
}

static struct kobj_attribute patch_enabled_attr =
	__ATTR(enabled, 0644, patch_enabled_show, patch_enabled_store);
static struct kobj_attribute patch_checksum_attr =
	__ATTR(checksum, 0444, patch_checksum_show, NULL);

static struct attribute *patch_attrs[] = {
	&patch_enabled_attr.attr,
	&patch_checksum_attr.attr,
	NULL,
};

static struct attribute_group patch_attr_group = {
	.attrs = patch_attrs,
};

static struct kpatch_object *patch_find_or_add_object(struct list_head *head,
						      const char *name)
{
	struct kpatch_object *object;

	list_for_each_entry(object, head, list) {
		if (!strcmp(object->name, name))
			return object;
	}

	object = kzalloc(sizeof(*object), GFP_KERNEL);
	if (!object)
		return NULL;

	object->name = name;
	INIT_LIST_HEAD(&object->funcs);
	INIT_LIST_HEAD(&object->dynrelas);
	INIT_LIST_HEAD(&object->hooks_load);
	INIT_LIST_HEAD(&object->hooks_unload);

	list_add_tail(&object->list, head);

	return object;
}

static void patch_free_objects(void)
{
	struct kpatch_object *object, *object_safe;
	struct kpatch_func *func, *func_safe;
	struct kpatch_dynrela *dynrela, *dynrela_safe;
	struct kpatch_hook *hook, *hook_safe;

	int i;

	list_for_each_entry_safe(object, object_safe, &kpmod.objects, list) {
		list_for_each_entry_safe(func, func_safe, &object->funcs,
					 list) {
			list_del(&func->list);
			kfree(func);
		}
		list_for_each_entry_safe(dynrela, dynrela_safe,
					 &object->dynrelas, list) {
			list_del(&dynrela->list);
			kfree(dynrela);
		}
		list_for_each_entry_safe(hook, hook_safe,
					 &object->hooks_load, list) {
			list_del(&hook->list);
			kfree(hook);
		}
		list_for_each_entry_safe(hook, hook_safe,
					 &object->hooks_unload, list) {
			list_del(&hook->list);
			kfree(hook);
		}
		list_del(&object->list);
		kfree(object);
	}

}

static int patch_is_func_forced(unsigned long addr)
{
	unsigned long *a;
	for (a = __kpatch_force_funcs; a < __kpatch_force_funcs_end; a++)
		if (*a == addr)
			return 1;
	return 0;
}

static int patch_make_funcs_list(struct list_head *objects)
{
	struct kpatch_object *object;
	struct kpatch_patch_func *p_func;
	struct kpatch_func *func;
	int i = 0, funcs_nr, ret;

	funcs_nr = __kpatch_funcs_end - __kpatch_funcs;

	for (p_func = __kpatch_funcs; p_func < __kpatch_funcs_end; p_func++) {
		object = patch_find_or_add_object(&kpmod.objects,
						  p_func->objname);
		if (!object)
			return -ENOMEM;

		func = kzalloc(sizeof(*func), GFP_KERNEL);
		if (!func)
			return -ENOMEM;

		func->new_addr = p_func->new_addr;
		func->new_size = p_func->new_size;

		if (!strcmp("vmlinux", object->name))
			func->old_addr = p_func->old_addr;
		else
			func->old_addr = 0x0;

		func->old_sympos = p_func->sympos;
		func->old_size = p_func->old_size;
		func->name = p_func->name;
		func->force = patch_is_func_forced(func->new_addr);
		list_add_tail(&func->list, &object->funcs);
	}

	return 0;
}

static int patch_make_dynrelas_list(struct list_head *objects)
{
	struct kpatch_object *object;
	struct kpatch_patch_dynrela *p_dynrela;
	struct kpatch_dynrela *dynrela;

	for (p_dynrela = __kpatch_dynrelas; p_dynrela < __kpatch_dynrelas_end;
	     p_dynrela++) {
		object = patch_find_or_add_object(objects, p_dynrela->objname);
		if (!object)
			return -ENOMEM;

		dynrela = kzalloc(sizeof(*dynrela), GFP_KERNEL);
		if (!dynrela)
			return -ENOMEM;

		dynrela->dest = p_dynrela->dest;
		dynrela->sympos = p_dynrela->sympos;
		dynrela->type = p_dynrela->type;
		dynrela->name = p_dynrela->name;
		dynrela->external = p_dynrela->external;
		dynrela->addend = p_dynrela->addend;
		list_add_tail(&dynrela->list, &object->dynrelas);
	}

	return 0;
}

static int patch_make_hook_lists(struct list_head *objects)
{
	struct kpatch_object *object;
	struct kpatch_patch_hook *p_hook;
	struct kpatch_hook *hook;

	for (p_hook = __kpatch_hooks_load; p_hook < __kpatch_hooks_load_end;
	     p_hook++) {
		object = patch_find_or_add_object(objects, p_hook->objname);
		if (!object)
			return -ENOMEM;

		hook = kzalloc(sizeof(*hook), GFP_KERNEL);
		if (!hook)
			return -ENOMEM;

		hook->hook = p_hook->hook;
		list_add_tail(&hook->list, &object->hooks_load);
	}

	for (p_hook = __kpatch_hooks_unload; p_hook < __kpatch_hooks_unload_end;
	     p_hook++) {
		object = patch_find_or_add_object(objects, p_hook->objname);
		if (!object)
			return -ENOMEM;

		hook = kzalloc(sizeof(*hook), GFP_KERNEL);
		if (!hook)
			return -ENOMEM;

		hook->hook = p_hook->hook;
		list_add_tail(&hook->list, &object->hooks_unload);
	}
	return 0;
}

static int __init patch_init(void)
{
	int ret;

	patch_kobj = kobject_create_and_add(THIS_MODULE->name,
					    kpatch_patches_kobj);
	if (!patch_kobj)
		return -ENOMEM;

	kpmod.mod = THIS_MODULE;
	INIT_LIST_HEAD(&kpmod.objects);

	ret = patch_make_funcs_list(&kpmod.objects);
	if (ret)
		goto err_patch;

	ret = patch_make_dynrelas_list(&kpmod.objects);
	if (ret)
		goto err_patch;

	ret = patch_make_hook_lists(&kpmod.objects);
	if (ret)
		goto err_patch;

	ret = kpatch_register(&kpmod, replace);
	if (ret)
		goto err_patch;

	ret = sysfs_create_group(patch_kobj, &patch_attr_group);
	if (ret)
		goto err_sysfs;

	return 0;

err_sysfs:
	kpatch_unregister(&kpmod);
err_patch:
	kobject_put(patch_kobj);
	return ret;
}

static void __exit patch_exit(void)
{
	WARN_ON(kpmod.enabled);

	patch_free_objects();
	sysfs_remove_group(patch_kobj, &patch_attr_group);
	kobject_put(patch_kobj);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
