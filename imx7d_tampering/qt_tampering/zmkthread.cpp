/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <sys/mman.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "zmkthread.h"
#include "utils.h"

#define get_SNVS_reg(virt_addr, add_offset)  (unsigned int*)(((void*)virt_addr)+add_offset)
const unsigned int ZMK_REG = 0x6c;
const unsigned int SNVS_BASE_ADDRESS_IMX7D = 0x30370000;

void ZmkThread::start()
{
    unsigned int snvs_base_address = 0;
    unsigned int zmk_read_value;
    unsigned int *mem = NULL;
    unsigned int zmk_value;
    int fd = 0;

    this->zmk_thread_stop = false;
    if (!strcmp(platform->toStdString().c_str(), "i.MX7D"))
        snvs_base_address = SNVS_BASE_ADDRESS_IMX7D;
    else
        return;

    fd = open("/dev/mem", O_SYNC | O_RDWR);

    if (fd < 0) {
        perror ("Can't open /dev/mem ! \n");
        exit(-1);
    }

    snvs_base_address = SNVS_BASE_ADDRESS_IMX7D;

    mem = (unsigned int *)mmap (NULL, 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, snvs_base_address);
    if (mem == MAP_FAILED) {
        perror ("Can't map memory, maybe the address is not truncated\n");
        exit(-1);
    }

    zmk_value = *get_SNVS_reg(mem, ZMK_REG);
    this->zmkValueLineEdit->setText(QString("0x") + QString::number(zmk_value, 16));

    while (!zmk_thread_stop) {
        zmk_read_value = *(get_SNVS_reg(mem, ZMK_REG));
        if (zmk_read_value != zmk_value ) {
            zmk_value = zmk_read_value;
            this->zmkValueLineEdit->setText(QString("0x") + QString::number(zmk_read_value, 16));
            if (zmk_read_value == 0) {
                this->zmkValueLineEdit->setDisabled(true);
                this->valueOfZmkLabel->setStyleSheet("QLabel { color : red }");
                this->valueOfZmkLabel->setText("TAMPERING VIOLATION TRIGGERED");
                this->zmkValueShowLabel->setStyleSheet("QLabel { color : red }");
                this->zmkValueShowLabel->setText("ZMK WAS CLEARED BY SNVS!");
            }
            emit append_line_zmk(QString("Value of ZMK changed to 0x") + QString::number(zmk_value, 16));
        }
        QThread::currentThread()->msleep(100);
    }
}

void ZmkThread::stop()
{
    this->zmk_thread_stop = true;
}

ZmkThread::ZmkThread(QString *platform,
            QLineEdit *zmkValueLineEdit,
            QLabel *zmkValueShowLabel,
            QLabel *valueOfZmkLabel)
{
    this->platform = platform;
    this->zmkValueLineEdit = zmkValueLineEdit;
    this->valueOfZmkLabel = valueOfZmkLabel;
    this->zmkValueShowLabel = zmkValueShowLabel;
}

