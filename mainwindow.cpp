#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "sniffing.h"
#include <QThread>
#include <QMessageBox>
//(https:\\/\\/)[a-zA-Z0-9\\.\\/\\=\\#\\%\\&\\(\\)\\+\\-\\*\\?]+

QString g_regexHttp     ("(http:\\/\\/[a-zA-Z0-9\\.\\/\\=\\#\\%\\&\\(\\)\\+\\-\\*\\?]+");
QString g_regexHttpS    ("(https:\\/\\/)?[a-zA-Z0-9\\.\\/\\=\\#\\%\\&\\(\\)\\+\\-\\*\\?]+");
QString g_regexUsername ("(login:)");
QString g_regexPassword ("[a-z0-9_-]{6,18}$");
QString g_regexEmail    ("([a-z0-9_\\.-]+)@([\\da-z\\.-]+)\\.([a-z\\.]{2,6})$");
QString g_regexWWW      ("(www.)[a-zA-Z0-9\\.\\/\\=\\#\\%\\&\\(\\)\\+\\-\\*\\?]+");

using namespace std;

const int CNT_CODE_ENTER = 16777220;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->_lnTextForSearchHeader->setVisible(false);
    ui->_lnTextForSearchData->setVisible(false);
    ui->_lnLengthFindData->setVisible(false);

    m_regex = " ";
    m_lengtFindExpression = 0;

    m_allTextField = new QTextDocument();

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
    bool _found = false;

    QTextCursor _highlightCursor(m_allTextField);
    _highlightCursor.setVisualNavigation(true);
    QTextCursor _cursor(m_allTextField);

    _cursor.beginEditBlock();

    QTextCharFormat _plainFormat(_highlightCursor.charFormat());
    QTextCharFormat _colorFormat = _plainFormat;
    _colorFormat.setForeground(Qt::green);

    QString _allText = ui->_textEdit->toPlainText();
    while (!_highlightCursor.isNull() && !_highlightCursor.atEnd())
    {
        _highlightCursor = m_allTextField->find(m_strForFind, _highlightCursor, QTextDocument::FindWholeWords);

        if (!_highlightCursor.isNull())
        {
            _found = true;
            _highlightCursor.movePosition(QTextCursor::WordRight,
                                          QTextCursor::KeepAnchor);
            _highlightCursor.mergeCharFormat(_colorFormat);

            int _quentityMatches = 0;
             for (int i = 0; i < _allText.size() - m_strForFind.size(); i += m_strForFind.size())
             {
                QString _str = "";
                for (int i = 0; i < m_strForFind.size(); i++)
                {
                    _str += _allText[i];
                }
                _allText.remove(0, m_strForFind.size());

                if (_str != m_strForFind)
                {
                    continue;
                }
                else
                {
                    QString _strForAppendInEdit = _str;
                    for (int i = 0; i < m_lengtFindExpression; i++)
                    {
                        _strForAppendInEdit += _allText[i];
                    }
                    _allText.remove(0, m_lengtFindExpression);
                    ui->_lnTextFindWord->append(_strForAppendInEdit);
                    i += m_lengtFindExpression;
                }
             }
        }
    }
     _cursor.endEditBlock();

     if (!_found)
     {
          QMessageBox::information(this, tr("Слово не знайдено"),
              "Вибачте, введене слово не знайдено(((");
     }
}

/*virtual*/ void MainWindow::keyPressEvent(QKeyEvent *i_event)
{
    int _key = i_event->key();
    if (_key == CNT_CODE_ENTER)
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
                //m_allTextField = ui->tableWidget;
                Find();
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
                m_lengtFindExpression = 0;
                m_lengtFindExpression = ui->_lnLengthFindData->text().toInt();
                m_allTextField = ui->_textEdit->document();
                Find();
            }
            ui->_textEdit->setFocus();
        }
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
        ui->_lnLengthFindData->setVisible(true);
        this->setFocusProxy(ui->_lnTextForSearchData);
        m_stateFind = StateFind::IN_DATA;
    }
}

void MainWindow::ReadDataRegex()
{
    QString _dataClient;
    for (int i = 0; i < Sniffing::m_vecClientData.size(); i++)
    {
        _dataClient += Sniffing::m_vecClientData[i];
    }

    ui->_textEdit->append(QString("\t\t\t\t Client Data \n"));
    QRegularExpression _regExpression(m_regex);
    QRegularExpressionMatch _match = _regExpression.match(_dataClient);
    if (_match.hasMatch())
    {
        for (int i = 1; i <= _match.lastCapturedIndex(); i++)
        {
            ui->_textEdit->append(_match.captured(i));
        }
    }

    ui->_textEdit->append(QString("\t\t\t\t Server Data \n"));
    QString _dataServer;
    for (int i = 0; i < Sniffing::m_vecServerData.size(); i++)
    {
        _dataServer += Sniffing::m_vecServerData[i];
    }

    _match = _regExpression.match(_dataServer);
    if (_match.hasMatch())
    {
        for (int i = 1; i < _match.lastCapturedIndex(); i++)
        {
            ui->_textEdit->append(_match.captured(i));
        }
    }
}

void MainWindow::ReadDataAll()
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
}

void MainWindow::ReadData()
{
    if (m_regex == " ")
    {
        ReadDataAll();
    }
    else
    {
        ReadDataRegex();
    }

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

void MainWindow::on__btnPause_clicked()
{
    m_sniffing->PauseSniffing();
}

void MainWindow::on__btnContinue_clicked()
{
    m_sniffing->ContinueSniffing();
}

void MainWindow::on__chHttp_stateChanged(int arg1)
{
    if (arg1 == Qt::Checked)
    {
        m_regex = g_regexHttp;
    }
}

void MainWindow::on__chHttps_stateChanged(int arg1)
{
    if (arg1 == Qt::Checked)
    {
        m_regex = g_regexHttpS;
    }
}

void MainWindow::on__chUsername_stateChanged(int arg1)
{
    if (arg1 == Qt::Checked)
    {
        m_regex = g_regexUsername;
    }
}

void MainWindow::on__chEmail_stateChanged(int arg1)
{
    if (arg1 == Qt::Checked)
    {
        m_regex = g_regexEmail;
    }
}

void MainWindow::on__chPassword_stateChanged(int arg1)
{
    if (arg1 == Qt::Checked)
    {
        m_regex = g_regexPassword;
    }
}
