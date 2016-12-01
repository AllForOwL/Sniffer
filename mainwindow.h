#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniffing.h"
#include <QShortcut>
#include <QKeyEvent>
#include <QTextDocument>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:

    enum StateFind
    {
        IN_HEADER,
        IN_DATA
    };

    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void ReadDataRegex();
    void ReadDataAll();

    void Find();

private slots:
    void AddThreadForSniffing();
    void AddPacketToTable(QString i_id,
                          QString i_time,
                          QString i_src,
                          QString i_dst,
                          QString i_protocol,
                          QString i_length,
                          QString i_info);
    void ReadData();

    void on__btnStop_clicked();

    void on__btnPause_clicked();

    void on_pushButton_clicked();

    void on__btnContinue_clicked();

    void ShowLineForFind();

    virtual void keyPressEvent(QKeyEvent* i_event);

    void on__chbHttp_stateChanged(int arg1);

    void on__chbHttps_stateChanged(int arg1);

    void on__chbUsername_stateChanged(int arg1);

    void on__chbPassword_stateChanged(int arg1);

    void on_checkBox_stateChanged(int arg1);

    void on_checkBox_2_stateChanged(int arg1);

    void on__chHttp_stateChanged(int arg1);

    void on__chHttps_stateChanged(int arg1);

    void on__chUsername_stateChanged(int arg1);

    void on__chEmail_stateChanged(int arg1);

    void on__chPassword_stateChanged(int arg1);

signals:
    void CompleteWriteData();
    void CompleteWritePacket();

private:
    Ui::MainWindow *ui;
    Sniffing* m_sniffing;
    QShortcut* m_find;
    StateFind m_stateFind;
    QString m_strForFind;

    QTextDocument*  m_allTextField;
    QString m_regex;
};

#endif // MAINWINDOW_H
