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
    ui->_lnTextForSearchHeader->setVisible(false);
    ui->_lnTextForSearchData->setVisible(false);

    m_stateFind = StateFind::IN_DATA;

    m_sniffing = new Sniffing(*this);

    connect(ui->_btnStart, SIGNAL(clicked(bool)), this, SLOT(AddThreadForSniffing()));
    connect(m_sniffing, SIGNAL(CompleteReadPacket(QString,QString,QString,QString,QString,QString,QString)), this,
            SLOT(AddPacketToTable(QString,QString,QString,QString,QString,QString,QString)));

    m_find = new QShortcut(QKeySequence("Ctrl+F"), this);
    connect(m_find, SIGNAL(activated()), this, SLOT(ShowLineForFind()));
    m_find->setAutoRepeat(false);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::Find()
{
    //std::string _str = ui->_textEdit->placeholderText();

    //std::find(_str.begin(), _str.end(), m_strForFind);
}

/*virtual*/ void MainWindow::keyPressEvent(QKeyEvent *i_event)
{
    if (i_event->key() == Qt::Key_Enter)
    {
        if (m_stateFind == StateFind::IN_HEADER)
        {
            if (ui->_lnTextForSearchHeader->text() == "")
            {
                ui->_lnTextForSearchHeader->setPalette(QPalette(Qt::red));
            }
            else
            {
                ui->_lnTextForSearchHeader->setPalette(QPalette(Qt::green));
                m_strForFind = ui->_lnTextForSearchHeader->text();
            }
            ui->tableWidget->setFocus();
        }
        else
        {
            if (ui->_lnTextForSearchData->text() == "")
            {
                ui->_lnTextForSearchData->setPalette(QPalette(Qt::red));
            }
            else
            {
                ui->_lnTextForSearchData->setPalette(QPalette(Qt::green));
                m_strForFind = ui->_lnTextForSearchData->text();
            }
            ui->_textEdit->setFocus();
        }

        Find();
    }
}

void MainWindow::ShowLineForFind()
{
    if (this->focusWidget() == ui->tableWidget)
    {
        ui->_lnTextForSearchHeader->setVisible(true);
        this->setFocusProxy(ui->_lnTextForSearchHeader);
        m_stateFind = StateFind::IN_HEADER;
    }
    else if (this->focusWidget() == ui->_textEdit)
    {
        ui->_lnTextForSearchData->setVisible(true);
        this->setFocusProxy(ui->_lnTextForSearchData);
        m_stateFind = StateFind::IN_DATA;
    }
}

void MainWindow::ReadData()
{
    ui->_textEdit->append(QString("\t\t\t\t Client Data \n"));
    QString _clientData = "";
    QString _symbol = " ";
    QChar    _chSymbol = ' ';
    for (int i = 0; i < Sniffing::m_vecClientData.size(); i++)
    {
        _symbol = Sniffing::m_vecClientData[i];
        _chSymbol = _symbol.at(0);
        if (_chSymbol.unicode() >= 32 && _chSymbol.unicode() <= 127)
        {
            _clientData += _chSymbol;
        }
    }
    ui->_textEdit->append(_clientData);

    ui->_textEdit->append(QString("\t\t\t\t Server Data \n"));
    QString _serverData = "";
    for (int i = 0; i < Sniffing::m_vecServerData.size(); i++)
    {
        _symbol = Sniffing::m_vecServerData[i];
        _chSymbol = _symbol.at(0);
        if (_chSymbol.unicode() >= 32 && _chSymbol.unicode() <= 127)
        {
            _serverData += _chSymbol;
        }
    }
    ui->_textEdit->append(_serverData);

    emit CompleteWriteData();
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

   emit CompleteWritePacket();
}

void MainWindow::AddThreadForSniffing()
{
    QThread* _pThread = new QThread();
    m_sniffing->moveToThread(_pThread);

    connect(_pThread,   SIGNAL(started()),  m_sniffing, SLOT(StartSniffing()));
    connect(_pThread,   SIGNAL(finished()), _pThread,   SLOT(deleteLater()));

    _pThread->start();
}

void MainWindow::on__btnStop_clicked()
{
    m_sniffing->StopSniffing();
}

/*  Tasks on today(29:11:2016)
 * - find string!!!;
 * - one line;
 * - working button "stop";
*/

void MainWindow::on__btnPause_clicked()
{
    m_sniffing->PauseSniffing();
}

void MainWindow::on__btnContinue_clicked()
{
    m_sniffing->ContinueSniffing();
}
