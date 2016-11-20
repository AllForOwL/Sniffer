#include "sniffing.h"
#include <vector>
#include <tins/tins.h>
#include <fstream>
#include <QFile>
#include <QMessageBox>
#include <QTextStream>
#include <QThread>

using namespace Tins;

Sniffing::Sniffing()
{

}

void Sniffing::StartSniffing()
{
    Packet _packet;
    Sniffer sniffer("eth0");

    while(true)
    {
        _packet  = sniffer.next_packet();

        if (_packet.pdu()->find_pdu<IP>())
        {
            QFile file("/tmp/packet.txt");

             std::ofstream _writeIP("/tmp/packet.txt");
             _writeIP <<_packet.pdu()->rfind_pdu<IP>().id()                 << std::endl;
             _writeIP <<_packet.pdu()->rfind_pdu<IP>().frag_off()      << std::endl;
             _writeIP <<_packet.pdu()->rfind_pdu<IP>().src_addr()           << std::endl;
             _writeIP <<_packet.pdu()->rfind_pdu<IP>().dst_addr()           << std::endl;
             _writeIP <<_packet.pdu()->rfind_pdu<IP>().protocol()  << std::endl;
             _writeIP <<_packet.pdu()->rfind_pdu<IP>().size()               << std::endl;
             _writeIP <<_packet.pdu()->rfind_pdu<IP>().fragment_offset()   << std::endl;


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
    }
}
