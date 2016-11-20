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
    void ReadIP(QString i_ip);
public slots:
    void StartSniffing();
};

#endif // SNIFFING_H
