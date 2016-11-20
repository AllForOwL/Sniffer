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
    connect(m_sniffing, SIGNAL(CompleteReadPacket(QString,QString,QString,QString,QString,QString,QString)), this,
            SLOT(AddPacketToTable(QString,QString,QString,QString,QString,QString,QString)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::AddPacketToTable(QString i_id,
                                  QString i_time,
                                  QString i_src,
                                  QString i_dst,
                                  QString i_protocol,
                                  QString i_length,
                                  QString i_info)
{
   ui->tableWidget->setRowCount(ui->tableWidget->rowCount() + 1);
   QTableWidgetItem* _addItem = new QTableWidgetItem;
   _addItem->setText(i_id);
   ui->tableWidget->setItem(ui->tableWidget->rowCount() -  1, 0, _addItem);

   QTableWidgetItem* _addItem2 = new QTableWidgetItem;
   _addItem2->setText(i_time);
   ui->tableWidget->setItem(ui->tableWidget->rowCount() -  1, 1, _addItem2);

   QTableWidgetItem* _addItem3 = new QTableWidgetItem;
   _addItem3->setText(i_src);
   ui->tableWidget->setItem(ui->tableWidget->rowCount() -  1, 2, _addItem3);

   QTableWidgetItem* _addItem4 = new QTableWidgetItem;
   _addItem4->setText(i_dst);
   ui->tableWidget->setItem(ui->tableWidget->rowCount() -  1, 3, _addItem4);

   QTableWidgetItem* _addItem5 = new QTableWidgetItem;
   _addItem5->setText(i_protocol);
   ui->tableWidget->setItem(ui->tableWidget->rowCount() -  1, 4, _addItem5);

   QTableWidgetItem* _addItem6 = new QTableWidgetItem;
   _addItem6->setText(i_length);
   ui->tableWidget->setItem(ui->tableWidget->rowCount() -  1, 5, _addItem6);

   QTableWidgetItem* _addItem7 = new QTableWidgetItem;
   _addItem7->setText(i_info);
   ui->tableWidget->setItem(ui->tableWidget->rowCount() -  1, 6, _addItem7);
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