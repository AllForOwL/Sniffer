#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "sniffing.h"
#include <QThread>

using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_sniffing = new Sniffing();

    connect(ui->_btnStart, SIGNAL(clicked(bool)), this, SLOT(AddThreadForSniffing()));
    connect(m_sniffing, SIGNAL(ReadIP(QString)), this, SLOT(AddIPToTable(QString)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::AddIPToTable(QString i_IP)
{
   QString _ip(i_IP);

   ui->tableWidget->setRowCount(ui->tableWidget->rowCount() + 1);
   QTableWidgetItem* _addItem = new QTableWidgetItem;
   _addItem->setText(_ip);
   ui->tableWidget->setItem(ui->tableWidget->rowCount() -  1,0, _addItem);
}

void MainWindow::AddThreadForSniffing()
{
    QThread* _pThread = new QThread();
    m_sniffing->moveToThread(_pThread);

    connect(_pThread,   SIGNAL(started()),  m_sniffing, SLOT(StartSniffing()));
    connect(_pThread,   SIGNAL(finished()), _pThread,   SLOT(deleteLater()));

    _pThread->start();
}

void MainWindow::on__btnStart_clicked()
{

}
