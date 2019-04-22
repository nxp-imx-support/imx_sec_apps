/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TAMPER_THREAD_H
#define TAMPER_THREAD_H

#include <QLabel>
#include <QThread>
#include <QString>
#include <QCheckBox>
#include <QPlainTextEdit>

class TamperThread : public QObject
{
  Q_OBJECT
private:
    QCheckBox *checkBox;
    QCheckBox *checkBox_2;
    QCheckBox *checkBox_3;
    QCheckBox *checkBox_4;
    QCheckBox *checkBox_5;
    QCheckBox *checkBox_6;
    QCheckBox *checkBox_7;
    QCheckBox *checkBox_8;
    QCheckBox *checkBox_9;
    QCheckBox *checkBox_10;
    QCheckBox *checkBox_11;
    QCheckBox *checkBox_12;
    QCheckBox *checkBox_13;
    QCheckBox *checkBox_14;
    QCheckBox *checkBox_15;
    QCheckBox *checkBox_16;
    QCheckBox *checkBox_17;
    QCheckBox *checkBox_18;
    QCheckBox *checkBox_19;
    QCheckBox *checkBox_20;
    QLabel *bottom_pins;
    QLabel *top_pins;
    QString *platform;
    QString *tampering;
    bool tamper_thread_stop;
public:
    TamperThread(QCheckBox *checkBox,
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
            QString *tampering);
    void start();

public slots:
    void stop();

signals:
    void append_line_tamp(QString line);
};

#endif // TAMPER_THREAD_T_H
