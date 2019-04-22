/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ZMKTHREAD_H
#define ZMKTHREAD_H

#include <QThread>
#include <QLabel>
#include <QPlainTextEdit>
#include <QLineEdit>

class ZmkThread : public QObject
{
    Q_OBJECT

private:
    QString *platform;
    QLineEdit *zmkValueLineEdit;
    QLabel *zmkValueShowLabel;
    QLabel *valueOfZmkLabel;
    bool zmk_thread_stop;
public:
    ZmkThread(QString *platform,
        QLineEdit *zmkValueLineEdit,
        QLabel *zmkValueShowLabel,
        QLabel *valueOfZmkLabel);
    void start();

public slots:
    void stop();

signals:
    void append_line_zmk(QString line);
};

#endif // ZMKTHREAD_H
