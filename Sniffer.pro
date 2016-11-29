#-------------------------------------------------
#
# Project created by QtCreator 2016-11-20T01:13:25
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Sniffer
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    sniffing.cpp

HEADERS  += mainwindow.h \
    sniffing.h

FORMS    += mainwindow.ui

LIBS += -ltins
