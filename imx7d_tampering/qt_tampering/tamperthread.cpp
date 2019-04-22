/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <QThread>

#include <sys/mman.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "tamperthread.h"
#include "utils.h"

#define get_SNVS_reg(virt_addr, add_offset)  (unsigned int*)(((void*)virt_addr)+add_offset)
unsigned int tamp_regs[2] = {0xa4, 0x4c};
const unsigned int SNVS_BASE_ADDRESS_IMX7D = 0x30370000;
const unsigned int SNVS_BASE_ADDRESS_IMX6UL = 0x020CC000;
const unsigned int TAMP_INITIAL_STAUTS1 = 0x00000000;
const unsigned int TAMP_INITIAL_STAUTS2 = 0x40000000;

void TamperThread::start()
{
    unsigned int tamp_initial_status1;
    unsigned int tamp_initial_status2;
    unsigned int tamp_actual_status1;
    unsigned int tamp_actual_status2;
    unsigned int snvs_base_address;
    unsigned int *mem = NULL;
    int fd = 0;

    this->tamper_thread_stop = false;

    if (!strcmp(platform->toStdString().c_str(), "i.MX7D")) {
        snvs_base_address = SNVS_BASE_ADDRESS_IMX7D;
    } else if (!strcmp(platform->toStdString().c_str(), "i.MX6UL")) {
        snvs_base_address = SNVS_BASE_ADDRESS_IMX6UL;
    }

    fd = open("/dev/mem", O_SYNC | O_RDWR);

    if (fd < 0) {
        perror ("Can't open /dev/mem ! \n");
        exit(-1);
    }

    mem = (unsigned int *)mmap (NULL, 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, snvs_base_address);
    if (mem == MAP_FAILED) {
        perror ("Can't map memory, maybe the address is not truncated\n");
        exit(-1);
    }

    if (!strcmp(tampering->toStdString().c_str(), "Passive")) {
        tamp_initial_status1 = TAMP_INITIAL_STAUTS1;
        tamp_initial_status2 = TAMP_INITIAL_STAUTS2;
        top_pins->setText("    GND");
        bottom_pins->setText("    VCC");
        checkBox->setChecked(false);
        checkBox->setDisabled(true);
        checkBox_2->setChecked(false);
        checkBox_2->setDisabled(true);
        checkBox_3->setChecked(false);
        checkBox_3->setDisabled(true);
        checkBox_4->setChecked(false);
        checkBox_4->setDisabled(true);
        checkBox_5->setChecked(false);
        checkBox_5->setDisabled(true);
        checkBox_6->setChecked(false);
        checkBox_6->setDisabled(true);
        checkBox_7->setChecked(false);
        checkBox_7->setDisabled(true);
        checkBox_8->setChecked(false);
        checkBox_8->setDisabled(true);
        checkBox_9->setChecked(false);
        checkBox_9->setDisabled(true);
        checkBox_10->setChecked(false);
        checkBox_10->setDisabled(true);


        while (!tamper_thread_stop) {
            tamp_actual_status1 = *get_SNVS_reg(mem, tamp_regs[0]);
            tamp_actual_status2 = *get_SNVS_reg(mem, tamp_regs[1]);

            if ((tamp_actual_status1 != tamp_initial_status1) && checkBox_19->isEnabled()) {
                checkBox_19->setStyleSheet("QCheckBox { color: red }");
                checkBox_19->setChecked(true);
                checkBox_19->setDisabled(true);
                emit append_line_tamp(QString("Pin number 9 indicates that SNVS security has been violated"));
            }

            if ((tamp_actual_status2 & (1 << 9)) && checkBox_11->isEnabled()) {
                checkBox_11->setStyleSheet("QCheckBox { color: red }");
                checkBox_11->setChecked(true);
                checkBox_11->setDisabled(true);
                emit append_line_tamp(QString("Passive tampering detected on pin numer 1"));
            }
            if ((tamp_actual_status2 & (1 << 10)) && checkBox_12->isEnabled()) {
                checkBox_12->setStyleSheet("QCheckBox { color: red }");
                checkBox_12->setChecked(true);
                checkBox_12->setDisabled(true);
                emit append_line_tamp(QString("Passive tampering detected on pin numer 2"));
            }

            if ((tamp_actual_status1 & 1) && checkBox_13->isEnabled()) {
                checkBox_13->setStyleSheet("QCheckBox { color: red }");
                checkBox_13->setChecked(true);
                checkBox_13->setDisabled(true);
                emit append_line_tamp(QString("Passive tampering detected on pin numer 3"));
            }
            if ((tamp_actual_status1 & (1 << 1)) && checkBox_14->isEnabled()) {
                checkBox_14->setStyleSheet("QCheckBox { color: red }");
                checkBox_14->setChecked(true);
                checkBox_14->setDisabled(true);
                emit append_line_tamp(QString("Passive tampering detected on pin numer 4"));
            }
            if ((tamp_actual_status1 & (1 << 2)) && checkBox_15->isEnabled()) {
                checkBox_15->setStyleSheet("QCheckBox { color: red }");
                checkBox_15->setChecked(true);
                checkBox_15->setDisabled(true);
                emit append_line_tamp(QString("Passive tampering detected on pin numer 5"));
            }
            if ((tamp_actual_status1 & (1 << 3)) && checkBox_16->isEnabled()) {
                checkBox_16->setStyleSheet("QCheckBox { color: red }");
                checkBox_16->setChecked(true);
                checkBox_16->setDisabled(true);
                emit append_line_tamp(QString("Passive tampering detected on pin numer 6"));
            }
            if ((tamp_actual_status1 & (1 << 4)) && checkBox_17->isEnabled()) {
                checkBox_17->setStyleSheet("QCheckBox { color: red }");
                checkBox_17->setChecked(true);
                checkBox_17->setDisabled(true);
                emit append_line_tamp(QString("Passive tampering detected on pin numer 7"));
            }
            if ((tamp_actual_status1 & (1 << 5)) && checkBox_18->isEnabled()) {
                checkBox_18->setStyleSheet("QCheckBox { color: red }");
                checkBox_18->setChecked(true);
                checkBox_18->setDisabled(true);
                emit append_line_tamp(QString("Passive tampering detected on pin numer 8"));
            }
            if ((tamp_actual_status1 & (1 << 7)) && checkBox_20->isEnabled()) {
                checkBox_20->setStyleSheet("QCheckBox { color: red }");
                checkBox_20->setChecked(true);
                checkBox_20->setDisabled(true);
                emit append_line_tamp(QString("Passive tampering detected on pin numer 10"));
            }
            QThread::currentThread()->msleep(100);
        }

    } else if (!strcmp(tampering->toStdString().c_str(), "Active")) {
        tamp_actual_status1 = *get_SNVS_reg(mem, tamp_regs[0]);
        tamp_actual_status2 = *get_SNVS_reg(mem, tamp_regs[1]);
        if ((tamp_actual_status2 & (1 << 9)) && checkBox_20->isEnabled()) {
            checkBox_20->setStyleSheet("QCheckBox { color: red }");
            checkBox_20->setChecked(true);
            checkBox_20->setDisabled(true);
            emit append_line_tamp(QString("Active tampering detected on pin number 10"));
        }
        if ((tamp_actual_status2 & (1 << 10)) && checkBox_19->isEnabled()) {
            checkBox_19->setStyleSheet("QCheckBox { color: red }");
            checkBox_19->setChecked(true);
            checkBox_19 ->setDisabled(true);
            emit append_line_tamp(QString("Active tampering detected on pin number 9"));
        }
        if ((tamp_actual_status1 & 1) && checkBox_18->isEnabled()) {
            checkBox_18->setStyleSheet("QCheckBox { color: red }");
            checkBox_18->setChecked(true);
            checkBox_18->setDisabled(true);
            emit append_line_tamp(QString("Active tampering detected on pin number 8"));
        }
        if ((tamp_actual_status1 & (1 << 1)) && checkBox_17->isEnabled()) {
            checkBox_17->setStyleSheet("QCheckBox { color: red }");
            checkBox_17->setChecked(true);
            checkBox_17->setDisabled(true);
            emit append_line_tamp(QString("Active tampering detected on pin number 7"));
        }
        if ((tamp_actual_status1 & (1 << 2)) && checkBox_16->isEnabled()) {
            checkBox_16->setStyleSheet("QCheckBox { color: red }");
            checkBox_16->setChecked(true);
            checkBox_16->setDisabled(true);
            emit append_line_tamp(QString("Active tampering detected on pin number 6"));
        }
        while (!tamper_thread_stop) {
            tamp_actual_status1 = *get_SNVS_reg(mem, tamp_regs[0]);
            tamp_actual_status2 = *get_SNVS_reg(mem, tamp_regs[1]);
            if ((tamp_actual_status2 & (1 << 9)) && checkBox_20->isEnabled()) {
                checkBox_20->setStyleSheet("QCheckBox {     background-color: red;\
                                           border-style: outset;\
                                           border-width: 2px;\
                                           border-radius: 10px;\
                                           border-color: beige;\
                                           font: bold 14px;\
                                           padding: 6px; }");
                checkBox_20->setChecked(true);
                checkBox_20->setDisabled(true);
                emit append_line_tamp(QString("Active tampering detected on pin number 10"));
            }
            if ((tamp_actual_status2 & (1 << 10)) && checkBox_19->isEnabled()) {
                checkBox_19->setStyleSheet("QCheckBox {     background-color: red;\
                                           border-style: outset;\
                                           border-width: 2px;\
                                           border-radius: 10px;\
                                           border-color: beige;\
                                           font: bold 14px;\
                                           padding: 6px; }");
                checkBox_19->setChecked(true);
                checkBox_19 ->setDisabled(true);
                emit append_line_tamp(QString("Active tampering detected on pin number 9"));
            }
            if ((tamp_actual_status1 & 1) && checkBox_18->isEnabled()) {
                checkBox_18->setStyleSheet("QCheckBox {     background-color: red;\
                                           border-style: outset;\
                                           border-width: 2px;\
                                           border-radius: 10px;\
                                           border-color: beige;\
                                           font: bold 14px;\
                                           padding: 6px; }");
                checkBox_18->setChecked(true);
                checkBox_18->setDisabled(true);
                emit append_line_tamp(QString("Active tampering detected on pin number 8"));
            }
            if ((tamp_actual_status1 & (1 << 1)) && checkBox_17->isEnabled()) {
                checkBox_17->setStyleSheet("QCheckBox {     background-color: red;\
                                           border-style: outset;\
                                           border-width: 2px;\
                                           border-radius: 10px;\
                                           border-color: beige;\
                                           font: bold 14px;\
                                           padding: 6px; }");
                checkBox_17->setChecked(true);
                checkBox_17->setDisabled(true);
                emit append_line_tamp(QString("Active tampering detected on pin number 7"));
            }
            if ((tamp_actual_status1 & (1 << 2)) && checkBox_16->isEnabled()) {
                checkBox_16->setStyleSheet("QCheckBox {     background-color: red;\
                                           border-style: outset;\
                                           border-width: 2px;\
                                           border-radius: 10px;\
                                           border-color: beige;\
                                           font: bold 14px;\
                                           padding: 6px; }");
                checkBox_16->setChecked(true);
                checkBox_16->setDisabled(true);
                emit append_line_tamp(QString("Active tampering detected on pin number 6"));
            }
        }
    }
    close_file(fd);
}

void TamperThread::stop()
{
    this->tamper_thread_stop = true;
}

TamperThread::TamperThread(QCheckBox *checkBox,
                           QCheckBox *checkBox_2,
                           QCheckBox *checkBox_3,
                           QCheckBox *checkBox_4,
                           QCheckBox *checkBox_5,
                           QCheckBox *checkBox_6,
                           QCheckBox *checkBox_7,
                           QCheckBox *checkBox_8,
                           QCheckBox *checkBox_9,
                           QCheckBox *checkBox_10,
                           QCheckBox *checkBox_11,
                           QCheckBox *checkBox_12,
                           QCheckBox *checkBox_13,
                           QCheckBox *checkBox_14,
                           QCheckBox *checkBox_15,
                           QCheckBox *checkBox_16,
                           QCheckBox *checkBox_17,
                           QCheckBox *checkBox_18,
                           QCheckBox *checkBox_19,
                           QCheckBox *checkBox_20,
                           QLabel *bottom_pins,
                           QLabel *top_pins,
                           QString *platform,
                           QString *tampering)
{
    this->checkBox = checkBox;
    this->checkBox_2 = checkBox_2;
    this->checkBox_3 = checkBox_3;
    this->checkBox_4 = checkBox_4;
    this->checkBox_5 = checkBox_5;
    this->checkBox_6 = checkBox_6;
    this->checkBox_7 = checkBox_7;
    this->checkBox_8 = checkBox_8;
    this->checkBox_9 = checkBox_9;
    this->checkBox_10 = checkBox_10;
    this->checkBox_11 = checkBox_11;
    this->checkBox_12 = checkBox_12;
    this->checkBox_13 = checkBox_13;
    this->checkBox_14 = checkBox_14;
    this->checkBox_15 = checkBox_15;
    this->checkBox_16 = checkBox_16;
    this->checkBox_17 = checkBox_17;
    this->checkBox_18 = checkBox_18;
    this->checkBox_19 = checkBox_19;
    this->checkBox_20 = checkBox_20;
    this->bottom_pins = bottom_pins;
    this->top_pins = top_pins;
    this->platform = platform;
    this->tampering = tampering;
}

