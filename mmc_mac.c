#include "mmc.h"

#include <sys/mount.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <util.h>
#include <IOKit/storage/IOBDMediaBSDClient.h>

struct mmc_st {
    int handle;
};

MMC* MMC_open(const char* dev) {
    int handle = opendev((char*)dev, O_RDONLY | O_NONBLOCK, 0, NULL);
    if (handle < 0) return NULL;

    MMC* mmc = malloc(sizeof(MMC));
    mmc->handle = handle;

    return mmc;
}

void MMC_close(MMC* mmc) {
    close(mmc->handle);
    free(mmc);
}

int MMC_report_key(MMC* mmc, uint8_t agid, uint8_t key_format, uint8_t *buffer, uint16_t length) {
    dk_bd_report_key_t report_key = {0};
    report_key.format = key_format;
    report_key.keyClass = 0x02;
    report_key.grantID = agid;
    report_key.bufferLength = length;
    report_key.buffer = buffer;
    return ioctl(mmc->handle, DKIOCBDREPORTKEY, &report_key) != -1;
}

int MMC_send_key(MMC* mmc, uint8_t agid, uint8_t key_format, uint8_t *buffer, uint16_t length) {
    dk_bd_send_key_t send_key = {0};
    send_key.format = key_format;
    send_key.keyClass = 0x02;
    send_key.grantID = agid;
    send_key.bufferLength = length;
    send_key.buffer = buffer;
    return ioctl(mmc->handle, DKIOCBDSENDKEY, &send_key) != -1;
}
