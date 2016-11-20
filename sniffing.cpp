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
            QFile file("/tmp/ip.txt");

             std::ofstream _writeIP("/tmp/ip.txt");
            _writeIP << _packet.pdu()->rfind_pdu<IP>().src_addr() << std::endl;
            _writeIP.close();

            if(!file.open(QIODevice::ReadOnly))
            {
                QMessageBox::information(0, "error", file.errorString());
            }

            QTextStream _readFile(&file);
            while(!_readFile.atEnd())
            {
                QString _ip = _readFile.readLine();
                emit ReadIP(_ip);
            }
            file.close();
       }
    }
}
