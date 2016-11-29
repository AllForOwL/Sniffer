#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniffing.h"
#include <QShortcut>
#include <QKeyEvent>

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

signals:
    void CompleteWriteData();
    void CompleteWritePacket();

private:
    Ui::MainWindow *ui;
    Sniffing* m_sniffing;
    QShortcut* m_find;
    StateFind m_stateFind;
    QString m_strForFind;
};

#endif // MAINWINDOW_H
