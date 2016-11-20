#ifndef SNIFFING_H
#define SNIFFING_H

#include <QObject>
#include <QWidget>

class Sniffing : public QObject
{
    Q_OBJECT
public:
    Sniffing();

signals:
    void CompleteReadPacket(QString i_id,
                            QString i_time,
                            QString i_src,
                            QString i_dst,
                            QString i_protocol,
                            QString i_length,
                            QString i_info);
public slots:
    void StartSniffing();
};

#endif // SNIFFING_H
