#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniffing.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButton_clicked();
    void AddThreadForSniffing();
    void AddIPToTable(QString i_IP);

    void on__btnStart_clicked();

private:
    Ui::MainWindow *ui;
    Sniffing* m_sniffing;
};

#endif // MAINWINDOW_H
