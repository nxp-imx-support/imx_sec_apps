/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tamperwindow.h"
#include <QApplication>
#include <QThread>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    TamperWindow w;
    w.show();

    return a.exec();

    return 0;
}
