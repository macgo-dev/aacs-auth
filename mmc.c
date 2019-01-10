#include "mmc.h"

#include <string.h>

inline static uint16_t
be16dec(const uint8_t *buf)
{

    return (uint16_t)(buf[0] << 8 | buf[1]);
}

int MMC_report_agid(MMC* mmc, uint8_t* agid) {
    uint8_t buf[8] = {0};

    int ret = MMC_report_key(mmc, 0, 0x0, buf, sizeof(buf));
    if (ret && (be16dec(buf) == 0x6)) {
        *agid = buf[7]>>6;
        return 1;
    }
    return 0;
}

int MMC_invalidate_agid(MMC* mmc, uint8_t agid) {
    uint8_t buf[2] = {0};

    return MMC_report_key(mmc, agid, 0x3F, buf, sizeof(buf));
}

int MMC_send_host_cert(MMC* mmc, uint8_t agid, const uint8_t *nonce, const uint8_t *cert) {
    uint8_t buf[116] = {0};

    buf[1] = 0x72;
    memcpy(buf + 4, nonce, 20);
    memcpy(buf + 24, cert, 92);

    return MMC_send_key(mmc, agid, 0x01, buf, sizeof(buf));
}

int MMC_report_drive_cert(MMC* mmc, uint8_t agid, uint8_t *nonce, uint8_t *cert) {
    uint8_t buf[116] = {0};

    int ret = MMC_report_key(mmc, agid, 0x01, buf, sizeof(buf));
    if (ret && (be16dec(buf) == 0x72)) {
        memcpy(nonce, buf + 4, 20);
        memcpy(cert, buf + 24, 92);
        return 1;
    }
    return 0;
}

int MMC_send_host_key(MMC* mmc, uint8_t agid, const uint8_t *point, const uint8_t *signature) {
    uint8_t buf[84] = {0};

    buf[1] = 0x52;
    memcpy(buf + 4, point, 40);
    memcpy(buf + 44, signature, 40);
    return MMC_send_key(mmc, agid, 0x02, buf, sizeof(buf));
}

int MMC_report_drive_Key(MMC* mmc, uint8_t agid, uint8_t *point, uint8_t *signature) {
    uint8_t buf[84] = {0};

    int ret = MMC_report_key(mmc, agid, 0x02, buf, sizeof(buf));
    if (ret && be16dec(buf) == 0x52) {
        memcpy(point, buf + 4, 40);
        memcpy(signature, buf + 44, 40);
        return 1;
    }
    return 0;
}
