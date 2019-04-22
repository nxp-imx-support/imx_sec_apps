/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <QString>
#include <QThread>
#include <QMutex>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "tamperwindow.h"
#include "zmkthread.h"
#include "ui_tamperwindow.h"
#include "utils.h"

TamperWindow::TamperWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::TamperWindow)
{
    ui->setupUi(this);
    ui->platformBox->addItem("i.MX7D");
    ui->platformBox->addItem("i.MX6UL");
    ui->tamperBox->addItem("Passive");
    ui->tamperBox->addItem("Active");
    ui->zmkValueLineEdit->setText("0x");
    this->child_id = 0;
    tamper_thread = new TamperThread(
                ui->checkBox,
                ui->checkBox_2,
                ui->checkBox_3,
                ui->checkBox_4,
                ui->checkBox_5,
                ui->checkBox_6,
                ui->checkBox_7,
                ui->checkBox_8,
                ui->checkBox_9,
                ui->checkBox_10,
                ui->checkBox_11,
                ui->checkBox_12,
                ui->checkBox_13,
                ui->checkBox_14,
                ui->checkBox_15,
                ui->checkBox_16,
                ui->checkBox_17,
                ui->checkBox_18,
                ui->checkBox_19,
                ui->checkBox_20,
                ui->bottom_pins,
                ui->top_pins,
                &platform,
                &tampering);
    zmk_thread = new ZmkThread(
                &platform,
                ui->zmkValueLineEdit,
                ui->zmkValueShowLabel,
                ui->valueOfZmkLabel);
    ui->logPlainText->appendPlainText(QString("You may change this configuration according to your board and the tampering type wanted"));
    ui->logPlainText->appendPlainText(QString("However, click on OK button only when you want to write the current configuration on the board"));
    ui->logPlainText->appendPlainText(QString(""));
    ui->bottomPinsLogStatic->setStyleSheet("border: 1px solid black");
    ui->topPinsLogStatic->setStyleSheet("border: 1px solid black");
}

TamperWindow::~TamperWindow()
{
    // Stop the tampering and zmk threads
    emit tamp_on_stop();
    emit zmk_on_stop();

    if (from_tamper_pipe != 0)
        close_file(from_tamper_pipe);

    // Stop the tampering process
    if (child_id) {
        char buffer[] = {35};
        write(this->to_tamper_pipe , buffer, 1);
        waitpid(child_id, NULL, 0);
    }

    delete ui;
}

void TamperWindow::on_okButton_clicked()
{
    platform = ui->platformBox->currentText();
    tampering = ui->tamperBox->currentText();
    QString platform_imx7d("i.MX7D");
    QString tampering_passive("Passive");

    // Disable Choosing boxes and button
    ui->platformBox->setDisabled(true);
    ui->tamperBox->setDisabled(true);
    ui->okButton->setDisabled(true);

    // Show messages
    ui->logPlainText->appendPlainText("You have selected a " + platform +
                                      " platform and a " + tampering + " tampering");
    ui->logPlainText->appendPlainText(QString("This configuration is now written on the board.\n\
If you want another configuration, reset the board and start the application again\n"));
    //Display message
    if (!QString::compare(tampering, QString("Passive"))) {
        ui->logPlainText->appendPlainText("Top pins are now connected to GND. Bottom pins are now connected to VCC.\n\
The board will now compare the voltage from each bottom pin and will compare it to a fixed desired value\n\
If the two values differ, passive tampering will be acknowledged on that specific pin\n");
    } else {
        ui->logPlainText->appendPlainText("Top pins are now connected to GND. Bottom pins have now the following configuration:\n\
    1. The first five pins(1-5) are now Tamper pins\n\
    2. The last five pins(6-10) are now Active tampers\n\
The board will now compare the read voltage from each Active tamper pin and will compare it to a dynamic desired value\n\
Tamper pins are used with Active tampers to create voltage lines so that the voltage value from Active tampers match the desired value\n\
When an Active tamper does not have a connection line with a Tamper pin, active tampering will be acknowledged on that specific pin\n");
    }

    // Create pipes
    int qt_to_tamper[2];
    int tamper_to_qt[2];
    char buffer1[1000] = {0};
    char buffer4[4096] = {0};

    if (pipe(qt_to_tamper)) {
        ui->logPlainText->appendPlainText("Pipe1 failed");
        return;
    }
    if (pipe(tamper_to_qt)) {
        ui->logPlainText->appendPlainText("Pipe2 failed");
        return;
    }

    // Create Tampering process
    this->child_id = fork();
    if (this->child_id == 0) {
        // Tampering app process
        close_file(qt_to_tamper[1]);
        dup2(qt_to_tamper[0], 0);
        close_file(qt_to_tamper[0]);

        close_file(tamper_to_qt[0]);
        dup2(tamper_to_qt[1], 1);
        dup2(tamper_to_qt[1], 2);
        close_file(tamper_to_qt[1]);

        // Determine which binary to exec
        QString exec_name = QString::compare(platform, platform_imx7d) == 0 ?
                    "/home/root/engine/tampering/tamp7" : "/home/root/engine/tampering/tamp6";

        execlp(exec_name.toStdString().c_str(), exec_name.toStdString().c_str(), (char*)NULL);
    } else {
        // QT app process
        close_file(qt_to_tamper[0]);
        close_file(tamper_to_qt[1]);

        this->from_tamper_pipe = tamper_to_qt[0];
        this->to_tamper_pipe = qt_to_tamper[1];

        // Read the first text from tamp
        read(tamper_to_qt[0], buffer1, 1000);

        // Determine which type of tampering to run
        int type = QString::compare(tampering, tampering_passive);

        if (type) {
            char buffer2[] = {'r','u','n',' ','s','e','t','_','a','c','t','_','t','a','m','p',13};
            write(qt_to_tamper[1], buffer2, 17);
        } else {
            char buffer3[] = {'r','u','n',' ','s','e','t','_','p','a','s','s','i','v','e','_','t','a','m','p',13};
            write(qt_to_tamper[1], buffer3, 21);
        }

        QThread::sleep(1);

        read(tamper_to_qt[0], buffer4, 10000);
    }

    for (int i = 0; i < 4096; i++)
        if (buffer4[i] == '=') {
            buffer4[i] = 0;
            break;
        }

    // Create threads for reading
    connect(this->zmk_thread, &ZmkThread::append_line_zmk, this, &TamperWindow::log_append_line_zmk);
    connect(this, &TamperWindow::zmk_on_stop, this->zmk_thread, &ZmkThread::stop);
    QFuture<void> zmk_start = QtConcurrent::run(this->zmk_thread, &ZmkThread::start);

    // Disable ZMK feature if platform is not IMX7D
    if (!QString::compare(platform, platform_imx7d)) {
        connect(this->tamper_thread, &TamperThread::append_line_tamp, this, &TamperWindow::log_append_line_tamp);
        connect(this, &TamperWindow::tamp_on_stop, this->tamper_thread, &TamperThread::stop);
        QFuture<void> tamper_start = QtConcurrent::run(this->tamper_thread, &TamperThread::start);
    } else {
        ui->zmkValueLineEdit->setDisabled(true);
    }

    // Display result
    if (ui->messageButton->isChecked()) {
        QString str1("Output from Tamperig server: ");
        QString str2(buffer4+7);
        ui->logPlainText->appendPlainText(str1);
        ui->logPlainText->appendPlainText(str2);
    }
}

void TamperWindow::on_zmkValueLineEdit_returnPressed()
{
    int zmk_to_qt[2];
    char buffer[4097] = {0};
    char exec_name[] = "/home/root/engine/zmk/zmk";
    const char *param = ui->zmkValueLineEdit->text().toStdString().c_str();
    int pid;

    pipe(zmk_to_qt);

    if (!QString::compare(ui->platformBox->currentText(), QString("Passive")))
        return;

    pid = fork();
    if (pid == 0) {
        // Zmk process
        close_file(zmk_to_qt[0]);
        dup2(zmk_to_qt[1], 1);
        dup2(zmk_to_qt[1], 2);
        close_file(zmk_to_qt[1]);
        execlp(exec_name, exec_name, param, (char *)NULL);
    } else {
        // QT process
        close_file(zmk_to_qt[1]);
        QThread::sleep(1);
        read(zmk_to_qt[0], buffer, 4096);

        if (ui->messageButton->isChecked()) {
            QString str1(buffer);
            ui->logPlainText->appendPlainText(
                        QString("Output from ZMK server:"));
            ui->logPlainText->appendPlainText(str1);
        }
        waitpid(pid, NULL, 0);
        close_file(zmk_to_qt[0]);
    }
}

void TamperWindow::log_append_line_tamp(QString line)
{
    ui->logPlainText->appendPlainText(line);
}
void TamperWindow::log_append_line_zmk(QString line)
{
    ui->logPlainText->appendPlainText(line);
}

void TamperWindow::on_platformBox_currentIndexChanged(const QString &arg1)
{
    ui->logPlainText->appendPlainText(QString("Current Platform is now set to ") + arg1 + "\n");
    if (!QString::compare(arg1, "i.MX7D"))
        if (ui->tamperBox->count() == 1)
            ui->tamperBox->addItem("Active");

    if (!QString::compare(arg1, "i.MX6UL"))
        ui->tamperBox->removeItem(1);
}

void TamperWindow::on_tamperBox_currentIndexChanged(const QString &arg1)
{
    ui->logPlainText->clear();
    ui->logPlainText->appendPlainText(QString("Current Tampering type is now set to ") + arg1);
    if (!QString::compare(arg1, "Passive")) {
        ui->activeTampers->setText("");
        ui->activeTampers->setStyleSheet("QLabel { color: black }");
        ui->tamperPins->setText("");
        ui->tamperPins->setStyleSheet("QLabel { color: black }");
        ui->checkBox->setDisabled(false);
        ui->checkBox->setChecked(false);
        ui->checkBox_2->setDisabled(false);
        ui->checkBox_2->setChecked(false);
        ui->checkBox_3->setDisabled(false);
        ui->checkBox_3->setChecked(false);
        ui->checkBox_4->setDisabled(false);
        ui->checkBox_4->setChecked(false);
        ui->checkBox_5->setDisabled(false);
        ui->checkBox_5->setChecked(false);
        ui->checkBox_6->setDisabled(false);
        ui->checkBox_6->setChecked(false);
        ui->checkBox_7->setDisabled(false);
        ui->checkBox_7->setChecked(false);
        ui->checkBox_8->setDisabled(false);
        ui->checkBox_8->setChecked(false);
        ui->checkBox_9->setDisabled(false);
        ui->checkBox_9->setChecked(false);
        ui->checkBox_10->setDisabled(false);
        ui->checkBox_10->setChecked(false);
        ui->checkBox_11->setStyleSheet("QCheckBox { color: black }");
        ui->checkBox_12->setStyleSheet("QCheckBox { color: black }");
        ui->checkBox_13->setStyleSheet("QCheckBox { color: black }");
        ui->checkBox_14->setStyleSheet("QCheckBox { color: black }");
        ui->checkBox_15->setStyleSheet("QCheckBox { color: black }");
        ui->checkBox_16->setStyleSheet("QCheckBox { color: black }");
        ui->checkBox_17->setStyleSheet("QCheckBox { color: black }");
        ui->checkBox_18->setStyleSheet("QCheckBox { color: black }");
        ui->checkBox_19->setStyleSheet("QCheckBox { color: black }");
        ui->checkBox_20->setStyleSheet("QCheckBox { color: black }");
        ui->logPlainText->appendPlainText("If you want Passive tampering configuration to be written on the board, press OK\n");
    }

    if (!QString::compare(arg1, "Active")) {
        ui->activeTampers->setText("Active tampers");
        ui->activeTampers->setStyleSheet("QLabel { color: red }");
        ui->tamperPins->setText("Tamper pins");
        ui->tamperPins->setStyleSheet("QLabel { color: green }");
        ui->checkBox->setChecked(false);
        ui->checkBox->setDisabled(true);
        ui->checkBox_2->setChecked(false);
        ui->checkBox_2->setDisabled(true);
        ui->checkBox_3->setChecked(false);
        ui->checkBox_3->setDisabled(true);
        ui->checkBox_4->setChecked(false);
        ui->checkBox_4->setDisabled(true);
        ui->checkBox_5->setChecked(false);
        ui->checkBox_5->setDisabled(true);
        ui->checkBox_6->setChecked(false);
        ui->checkBox_6->setDisabled(true);
        ui->checkBox_7->setChecked(false);
        ui->checkBox_7->setDisabled(true);
        ui->checkBox_8->setChecked(false);
        ui->checkBox_8->setDisabled(true);
        ui->checkBox_9->setChecked(false);
        ui->checkBox_9->setDisabled(true);
        ui->checkBox_10->setChecked(false);
        ui->checkBox_10->setDisabled(true);
        ui->checkBox_11->setStyleSheet("QCheckBox { color: green }");
        ui->checkBox_12->setStyleSheet("QCheckBox { color: green }");
        ui->checkBox_13->setStyleSheet("QCheckBox { color: green }");
        ui->checkBox_14->setStyleSheet("QCheckBox { color: green }");
        ui->checkBox_15->setStyleSheet("QCheckBox { color: green }");
        ui->checkBox_16->setStyleSheet("QCheckBox { color: red }");
        ui->checkBox_17->setStyleSheet("QCheckBox { color: red }");
        ui->checkBox_18->setStyleSheet("QCheckBox { color: red }");
        ui->checkBox_19->setStyleSheet("QCheckBox { color: red }");
        ui->checkBox_20->setStyleSheet("QCheckBox { color: red }");
        ui->logPlainText->appendPlainText("If you wan Active tampering confiuration to be written on your board, follow the following steps:\n\
    1. Create a physical line between one Active tamper and one Tamper pin by connecting them using a wire\n\
    2. Press OK\n");
    }
}
