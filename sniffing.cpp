#include "sniffing.h"
#include <vector>
#include <fstream>
#include <QFile>
#include <QMessageBox>
#include <QTextStream>
#include <QThread>
#include "mainwindow.h"

const size_t MAX_PAYLOAD = 3 * 1024;

std::vector<QString> Sniffing::m_vecClientData;
std::vector<QString> Sniffing::m_vecServerData;

Sniffing* Sniffing::m_this = nullptr;
bool Sniffing::m_readPacket = true;

Sniffing::Sniffing(MainWindow& i_window) : m_mainWindow(&i_window)
{
    m_packet    = new Packet();
    m_sniffer   = new Sniffer("eth0");
    m_tcpStream = new StreamFollower();
    m_tcpStream->new_stream_callback(&on_new_connection);
    m_this      = this;
    m_stateSniff = StateSniff::WORKING;
    m_regex = " ";

    connect(this,           SIGNAL(StartReadData()),        this,           SLOT(ReadDataPacket()));
    connect(m_mainWindow,   SIGNAL(CompleteWriteData()),    this,           SLOT(ReadHeaderPacket()));
    connect(m_mainWindow,   SIGNAL(CompleteWritePacket()),  this,           SLOT(ReadNextPacket()));
    connect(m_this,         SIGNAL(CompleteReadData()),     m_mainWindow,   SLOT(ReadData()));
}

void Sniffing::StopSniffing()
{
    m_stateSniff = StateSniff::STOP;
    m_readPacket = false;
}

void Sniffing::PauseSniffing()
{
    m_stateSniff = StateSniff::PAUSE;
    m_readPacket = false;
}

void Sniffing::ContinueSniffing()
{
    m_stateSniff = StateSniff::WORKING;
    m_readPacket = true;
    StartSniffing();
}

void Sniffing::on_server_data(Stream& i_stream)
{
    const Stream::payload_type& _client_payload = i_stream.client_payload();
    const Stream::payload_type& _server_payload = i_stream.server_payload();

    m_vecClientData.clear();
    m_vecServerData.clear();

    for (int i = 0; i < _client_payload.size(); i++)
    {
        m_vecClientData.push_back(QString(_client_payload[i]));
    }
    for (int i = 0; i < _server_payload.size(); i++)
    {
        m_vecServerData.push_back(QString(_server_payload[i]));
    }

//    if (i_stream.server_payload().size() > MAX_PAYLOAD)
//    {
//      i_stream.ignore_server_data();
//    }

    m_readPacket = false;
    emit m_this->CompleteReadData();
}

void Sniffing::on_client_data(Stream& i_stream)
{
//    if (i_stream.client_payload().size() > MAX_PAYLOAD)
//    {
//        i_stream.ignore_client_data();
//    }
}

void Sniffing::on_new_connection(Stream& i_stream)
{
    i_stream.client_data_callback(&on_client_data);
    i_stream.server_data_callback(&on_server_data);

    i_stream.auto_cleanup_payloads(false);
}

void Sniffing::ReadDataPacket()
{
    m_tcpStream->process_packet(*m_packet);
}

void Sniffing::ReadHeaderPacket()
{
    m_stateSniff = StateSniff::READ_PACKET;

    const IP& _ip   = m_packet->pdu()->rfind_pdu<IP>();
    const TCP& _tcp = m_packet->pdu()->rfind_pdu<TCP>();

    QFile file("/tmp/packet.txt");

     std::ofstream _writeIP("/tmp/packet.txt");
     _writeIP <<_ip.id()        << std::endl;
     _writeIP <<_ip.src_addr()  << std::endl;
     _writeIP <<_ip.dst_addr()  << std::endl;
     _writeIP <<_ip.protocol()  << std::endl;
     _writeIP <<_tcp.size()     << std::endl;
     _writeIP <<_tcp.sport()    << std::endl;
     _writeIP <<_tcp.dport()    << std::endl;


    _writeIP.close();

    if(!file.open(QIODevice::ReadOnly))
    {
        QMessageBox::information(0, "error", file.errorString());
    }

    QTextStream _readFile(&file);
    while(!_readFile.atEnd())
    {
        QString _id         = _readFile.readLine();
        QString _time       = _readFile.readLine();
        QString _src        = _readFile.readLine();
        QString _dst        = _readFile.readLine();
        QString _protocol   = _readFile.readLine();
        QString _size       = _readFile.readLine();
        QString _info       = _readFile.readLine();
        emit CompleteReadPacket(_id, _time, _src, _dst, _protocol, _size, _info);
    }
    file.close();
}

void Sniffing::ReadNextPacket()
{
    if (m_stateSniff == StateSniff::READ_PACKET)
    {
        m_stateSniff = StateSniff::WORKING;
        m_readPacket = true;
        StartSniffing();
    }
}

void Sniffing::StartSniffing()
{
    while(m_readPacket)
    {
        *m_packet  = m_sniffer->next_packet();
        if (m_packet->pdu()->find_pdu<TCP>())
        {
           emit StartReadData();
        }
    }
}
