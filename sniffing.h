#ifndef SNIFFING_H
#define SNIFFING_H

#include <QObject>
#include <QWidget>
#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/sniffer.h>


using namespace Tins;
using Tins::Packet;
using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

class MainWindow;

class Sniffing : public QObject
{
    Q_OBJECT
public:
    Sniffing(MainWindow& i_window);
    static void on_server_data(Stream& i_stream);
    static void on_client_data(Stream& i_stream);
    static void on_new_connection(Stream& i_stream);

signals:
    void CompleteReadPacket(QString i_id,
                            QString i_time,
                            QString i_src,
                            QString i_dst,
                            QString i_protocol,
                            QString i_length,
                            QString i_info);

    void CompleteReadData();

    void ReadClientData(QString i_data);
    void ReadServerData(QString i_data);

    void StartReadData();
    void StartReadPacket();

public slots:
    void StartSniffing();
    void ReadDataPacket();
    void ReadHeaderPacket();
    void ReadNextPacket();

public:
    static std::vector<QString> m_vecClientData;
    static std::vector<QString> m_vecServerData;
    static Sniffing*            m_this;
    Packet*         m_packet;
    Sniffer*        m_sniffer;
    StreamFollower* m_tcpStream;
    MainWindow*     m_mainWindow;
    static bool m_readPacket;
};

#endif // SNIFFING_H
