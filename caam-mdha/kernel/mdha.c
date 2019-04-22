/*
 * Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "compat.h"
#include "intern.h"
#include "sm.h"
#include "mdha.h"
#include "desc.h"
#include "jr.h"

#include "linux/printk.h"

static struct kobject *mdha_kobj;
static struct kobj_attribute *mdha_kattr;
static struct attribute_group *mdha_attr_group;

static int mdha_major;
static struct class *mdha_class;

mdha_addr_t mdha_addr_user;

struct mdha_operaion_result {
	struct completion completion;
	int err;
};

static void mdha_operation_done(struct device *dev, u32 *desc, u32 err, void *context)
{
	struct mdha_operaion_result *res = context;

	#ifdef DEBUG
	dev_err(dev, "%s %d: err 0x%x\n", __func__, __LINE__, err);
	#endif

	res->err = err;

	complete(&res->completion);
}

static int mdha_operation(struct device *ksdev, u8* data, u8* digest, u32 sz, u32 operation)
{
	struct caam_drv_private_sm *kspriv = dev_get_drvdata(ksdev);
	struct device *jrdev = kspriv->smringdev;
	struct mdha_operaion_result res;
	int ret = 0;

	u32 __iomem *desc;

	desc = (u32*)kzalloc(MAX_CAAM_DESCSIZE * sizeof(u32), GFP_KERNEL | GFP_DMA);
	if(!desc)
		return -ENOMEM;

	dma_addr_t indata_dma;
	dma_addr_t outdata_dma;

	indata_dma = dma_map_single(jrdev, data, sz, DMA_TO_DEVICE);
	dma_sync_single_for_device(jrdev, indata_dma, sz, DMA_TO_DEVICE);

	outdata_dma = dma_map_single(jrdev, digest, MAX_DIGEST_SIZE, DMA_FROM_DEVICE);

	desc[1] = CMD_OPERATION | OP_TYPE_CLASS2_ALG | OP_ALG_AAI_HASH | operation | OP_ALG_AS_INITFINAL;
	desc[2] = CMD_FIFO_LOAD | FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG | FIFOLDST_EXT | FIFOLD_TYPE_LAST2;
	desc[3] = (u32)indata_dma;
	desc[4] = (u32)sz;
	desc[5] = CMD_STORE | LDST_CLASS_2_CCB | LDST_SRCDST_BYTE_CONTEXT | (MAX_DIGEST_SIZE & LDST_LEN_MASK);
	desc[6] = (u32)outdata_dma;
	desc[0] = CMD_DESC_HDR | HDR_ONE | (7 & HDR_DESCLEN_MASK);

	res.err = 0;
	init_completion(&res.completion);

	ret = caam_jr_enqueue(jrdev, desc, mdha_operation_done, &res);
	if (!ret) {
		/* in progress */
		wait_for_completion_interruptible(&res.completion);
		ret = res.err;
	}

	dma_sync_single_for_cpu(jrdev, outdata_dma, MAX_DIGEST_SIZE, DMA_FROM_DEVICE);

	dma_unmap_single(jrdev, indata_dma, sz, DMA_TO_DEVICE);
	dma_unmap_single(jrdev, outdata_dma, MAX_DIGEST_SIZE, DMA_FROM_DEVICE);

	kfree(desc);

	return ret;
}

static ssize_t mdha_hash(u32 size)
{
	int ret = 0;
	struct device_node *dev_node;
	struct platform_device *pdev;
	struct device *ctrldev, *ksdev;
	struct caam_drv_private *ctrlpriv;
	struct caam_drv_private_sm *kspriv;
	u32 units, unit, keyslot;
	u8 *block, *digest;
	u32 operation;

	dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");
	if (!dev_node) {
		dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
		if (!dev_node)
			return -ENODEV;
	}

	pdev = of_find_device_by_node(dev_node);
	if (!pdev)
		return -ENODEV;

	ctrldev = &pdev->dev;
	ctrlpriv = dev_get_drvdata(ctrldev);
	ksdev = ctrlpriv->smdev;
	kspriv = dev_get_drvdata(ksdev);
	if (kspriv == NULL)
		return -ENODEV;

	block = kzalloc(MAX_BLOCK_SIZE, GFP_KERNEL | GFP_DMA);
	digest = kzalloc(MAX_DIGEST_SIZE, GFP_KERNEL | GFP_DMA);

	if(copy_from_user(block, mdha_addr_user.block, size))
		return -EFAULT;

	if(mdha_addr_user.algo == MD5)
		operation = OP_ALG_ALGSEL_MD5;
	else
		operation = OP_ALG_ALGSEL_SHA1;

	mdha_operation(ksdev, block, digest, size, operation);

	if (copy_to_user(mdha_addr_user.digest, digest, MAX_DIGEST_SIZE))
		return -EFAULT;

	return ret;
}

static long mdha_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int errval = 0;

	switch (cmd) {
		case MDHA_IOCTL_TASK:
		{
			u32 task_block_size;

			if (copy_from_user(&task_block_size, (u32 *)arg, sizeof(u32)))
				return -EFAULT;
			mdha_hash(task_block_size);
			break;
		}
		case MDHA_IOCTL_TASKS_TYPE:
		{
			if (copy_from_user(&mdha_addr_user, (mdha_addr_t *)arg, sizeof(mdha_addr_t)))
				return -EFAULT;
			break;
		}
		default:
		    break;
	}

	return errval;
}


static int mdha_open(struct inode *inode, struct file *file)
{
	int errval = 0;

	return errval;
}

static int mdha_release(struct inode *inode, struct file *file)
{
	int errval = 0;

	return errval;
}

static const struct file_operations mdha_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = mdha_ioctl,
	.open = mdha_open,
	.release = mdha_release,
};

static int __init mdha_init(void)
{
	struct device_node *dev_node;
	struct platform_device *pdev;

	struct attribute **attrs;
	int ret;

	dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");
	if (!dev_node) {
		dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
		if (!dev_node)
			return -ENODEV;
	}

	pdev = of_find_device_by_node(dev_node);
	if (!pdev)
		return -ENODEV;

	of_node_get(dev_node);

	/* The last one is NULL, which is used to detect the end */
	attrs = devm_kzalloc(&pdev->dev, 3 * sizeof(*attrs),
			     GFP_KERNEL);
	mdha_kattr = devm_kzalloc(&pdev->dev, 2 * sizeof(*mdha_kattr),
				 GFP_KERNEL);
	mdha_attr_group = devm_kzalloc(&pdev->dev, sizeof(*mdha_attr_group),
				      GFP_KERNEL);
	if (!attrs || !mdha_kattr || !mdha_attr_group)
		return -ENOMEM;

	sysfs_attr_init(mdha_kattr[0].attr);
	mdha_kattr[0].attr.name = "mdha";
	mdha_kattr[0].attr.mode = 0600;
	mdha_kattr[0].show = NULL;
	mdha_kattr[0].store = NULL;
	attrs[0] = &mdha_kattr[0].attr;

	mdha_attr_group->attrs = attrs;

	mdha_kobj = kobject_create_and_add("mdha", NULL);
	if (!mdha_kobj) {
		dev_err(&pdev->dev, "failed to add kobject\n");
		return -ENOMEM;
	}

	ret = sysfs_create_group(mdha_kobj, mdha_attr_group);
	if (ret) {
		dev_err(&pdev->dev, "failed to create sysfs group: %d\n", ret);
		kobject_put(mdha_kobj);
		return ret;
	}

	mdha_major = register_chrdev(0, "mdha", &mdha_fops);
	if (mdha_major < 0) {
		printk("mdha: Unable to register driver\n");
		return -ENODEV;
	}
	mdha_class = class_create(THIS_MODULE, "mdha");
	if (IS_ERR(mdha_class)) {
		printk("mdha: Unable to create class\n");
		unregister_chrdev(mdha_major, "mdha");
		return PTR_ERR(mdha_class);
	}
	device_create(mdha_class, NULL, MKDEV(mdha_major, 0), NULL, "mdha");

	return 0;
}

static void __exit mdha_exit(void)
{
	struct device_node *dev_node;
	struct platform_device *pdev;

	dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");
	if (!dev_node) {
		dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
		if (!dev_node)
			return;
	}

	pdev = of_find_device_by_node(dev_node);
	if (!pdev)
		return;

	of_node_put(dev_node);

	sysfs_remove_group(mdha_kobj, mdha_attr_group);
	kobject_put(mdha_kobj);

	device_destroy(mdha_class, MKDEV(mdha_major, 0));
	class_destroy(mdha_class);
	unregister_chrdev(mdha_major, "mdha");

	return;
}

module_init(mdha_init);
module_exit(mdha_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("FSL CAAM MDHA");
MODULE_AUTHOR("Freescale Semiconductor - MCU");
