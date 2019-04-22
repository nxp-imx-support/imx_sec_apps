/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TAMPERWINDOW_H
#define TAMPERWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QtConcurrent>

#include "tamperthread.h"
#include "zmkthread.h"

namespace Ui {
class TamperWindow;
}

class TamperWindow : public QMainWindow
{
    Q_OBJECT

public:
    int to_tamper_pipe;
    int from_tamper_pipe;
    QString platform;
    QString tampering;
    TamperThread *tamper_thread;
    ZmkThread *zmk_thread;
    int child_id;
    explicit TamperWindow(QWidget *parent = 0);
    ~TamperWindow();

private slots:
    void on_okButton_clicked();
    void on_zmkValueLineEdit_returnPressed();
    void on_platformBox_currentIndexChanged(const QString &arg1);

    void on_tamperBox_currentIndexChanged(const QString &arg1);

public slots:
    void log_append_line_tamp(QString line);
    void log_append_line_zmk(QString line);

signals:
    void tamp_on_stop();
    void zmk_on_stop();

private :
    Ui::TamperWindow *ui;
};

#endif // TAMPERWINDOW_H
