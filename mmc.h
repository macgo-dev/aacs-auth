#ifndef MMC_H
#define MMC_H

#include <stddef.h>
#include <stdint.h>

typedef struct mmc_st MMC;

MMC* MMC_open(const char* dev);
void MMC_close(MMC*);

int MMC_report_agid(MMC*, uint8_t* agid);
int MMC_invalidate_agid(MMC*, uint8_t agid);

int MMC_send_host_cert(MMC*, uint8_t agid, const uint8_t *nonce, const uint8_t *cert);
int MMC_report_drive_cert(MMC*, uint8_t agid, uint8_t *nonce, uint8_t *cert);
int MMC_send_host_key(MMC*, uint8_t agid, const uint8_t *point, const uint8_t *signature);
int MMC_report_drive_Key(MMC*, uint8_t agid, uint8_t *point, uint8_t *signature);

int MMC_report_key(MMC*, uint8_t agid, uint8_t key_format, uint8_t *buffer, uint16_t length);
int MMC_send_key(MMC*, uint8_t agid, uint8_t key_format, uint8_t *buffer, uint16_t length);

#endif // MMC_H
