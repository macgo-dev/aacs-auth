#include "mmc.h"
#include <stdio.h>

#include <Windows.h>

/* From <ntddscsi.h> */

#define MAX_SENSE_LEN 18 //Sense data max length
//Sense key codes..
#define SEN_KEY_NO_SEN      0x00 //No sense key info.
#define SEN_KEY_NOT_READY   0x02 //Device not ready error.
#define SEN_KEY_ILLEGAL_REQ 0x05 //Illegal request, error/s in parameters or cmd.

//Request sense return data format
typedef struct
{
    unsigned char response_code;
    unsigned char segment_no;
    unsigned char flags_sensekey;
    unsigned char info0;
    unsigned char info1;
    unsigned char info2;
    unsigned char info3;
    unsigned char add_len;
    unsigned char com_spec_info0;
    unsigned char com_spec_info1;
    unsigned char com_spec_info2;
    unsigned char com_spec_info3;
    unsigned char ASC;
    unsigned char ASCQ;
    unsigned char field_rep_ucode;
    unsigned char sen_key_spec15;
    unsigned char sen_key_spec16;
    unsigned char sen_key_spec17;
    unsigned char add_sen_bytes;
}T_sense_data;

//** Defines taken from ntddscsi.h in MS Windows DDK CD
#define SCSI_IOCTL_DATA_OUT             0 //Give data to SCSI device (e.g. for writing)
#define SCSI_IOCTL_DATA_IN              1 //Get data from SCSI device (e.g. for reading)
#define SCSI_IOCTL_DATA_UNSPECIFIED     2 //No data (e.g. for ejecting)

#define IOCTL_SCSI_PASS_THROUGH         0x4D004
typedef struct _SCSI_PASS_THROUGH {
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG * DataBufferOffset;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
}SCSI_PASS_THROUGH, *PSCSI_PASS_THROUGH;

#define IOCTL_SCSI_PASS_THROUGH_DIRECT  0x4D014
typedef struct _SCSI_PASS_THROUGH_DIRECT {
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    PVOID DataBuffer;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
}SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;
//** End of defines taken from ntddscsi.h from MS Windows DDK CD

typedef struct _SCSI_PASS_THROUGH_AND_BUFFERS {
    SCSI_PASS_THROUGH spt;
    BYTE DataBuffer[64*1024];
}T_SPT_BUFS;

typedef struct _SCSI_PASS_THROUGH_DIRECT_AND_SENSE_BUFFER {
    SCSI_PASS_THROUGH_DIRECT sptd;
    UCHAR SenseBuf[MAX_SENSE_LEN];
}T_SPDT_SBUF;

//SCSI return status codes.
#define STATUS_GOOD     0x00  // Status Good
#define STATUS_CHKCOND  0x02  // Check Condition
#define STATUS_CONDMET  0x04  // Condition Met
#define STATUS_BUSY     0x08  // Busy
#define STATUS_INTERM   0x10  // Intermediate
#define STATUS_INTCDMET 0x14  // Intermediate-condition met
#define STATUS_RESCONF  0x18  // Reservation conflict
#define STATUS_COMTERM  0x22  // Command Terminated
#define STATUS_QFULL    0x28  // Queue full
#define STATUS_ACA      0x30  // ACA active

#define CDB_SIZE 16

struct mmc_st {
    HANDLE handle;
};

MMC* MMC_open(const char* dev) {
    if (strlen(dev) != 2 || dev[1] != ':')
        return NULL;
    TCHAR target[] = {'\\', '\\', '.', '\\', dev[0], ':', 0};
    HANDLE h = CreateFile(target,
                          GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;

    MMC* mmc = malloc(sizeof(MMC));
    mmc->handle = h;

    return mmc;
}

void MMC_close(MMC* mmc) {
    CloseHandle(mmc->handle);
    free(mmc);
}

static int _sendCmd(HANDLE handle, const uint8_t *cmd, uint8_t *buf, size_t send, size_t recv) {
    T_SPDT_SBUF sptd_sb;  //Includes sense buffer
    DWORD dwBytesReturned;

    sptd_sb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sptd_sb.sptd.PathId = 0;    //SCSI card ID will be filled in automatically.
    sptd_sb.sptd.TargetId = 0;  //SCSI target ID will also be filled in.
    sptd_sb.sptd.Lun = 0;       //SCSI lun ID will also be filled in.
    sptd_sb.sptd.CdbLength = 12;  //CDB size.
    sptd_sb.sptd.SenseInfoLength = MAX_SENSE_LEN;  //Maximum length of sense data to retrieve.

    if (buf != NULL) {
        if (send > 0) {
            sptd_sb.sptd.DataIn = SCSI_IOCTL_DATA_OUT;  //There will be data going to the drive.
            sptd_sb.sptd.DataTransferLength = (ULONG) send;
            sptd_sb.sptd.DataBuffer = buf;
        } else if (recv > 0) {
            sptd_sb.sptd.DataIn = SCSI_IOCTL_DATA_IN;  //There will be data coming from the drive.
            sptd_sb.sptd.DataTransferLength = (ULONG) recv;
            sptd_sb.sptd.DataBuffer = buf;
        } else {
            sptd_sb.sptd.DataIn = SCSI_IOCTL_DATA_UNSPECIFIED;
            sptd_sb.sptd.DataTransferLength = 0;
            sptd_sb.sptd.DataBuffer = NULL;
        }
    } else {
        sptd_sb.sptd.DataIn = SCSI_IOCTL_DATA_UNSPECIFIED;
        sptd_sb.sptd.DataTransferLength = 0;
        sptd_sb.sptd.DataBuffer = NULL;
    }

    sptd_sb.sptd.TimeOutValue = 5;  //SCSI timeout value (max 5 sec).
    sptd_sb.sptd.SenseInfoOffset = sizeof(SCSI_PASS_THROUGH_DIRECT);

    //Copy CDB from cmd
    memcpy(sptd_sb.sptd.Cdb, cmd, 16);

    ZeroMemory(sptd_sb.SenseBuf, MAX_SENSE_LEN);

    //Send the command to drive.
    if (DeviceIoControl(handle, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                        (PVOID)(&sptd_sb),
                        (DWORD)(sizeof(sptd_sb)),
                        (PVOID)(&sptd_sb),
                        (DWORD)(sizeof(sptd_sb)),
                        &dwBytesReturned, NULL)) {
        // The command status MUST be checked because the I/O-Command can succeed but still return a status error!!!
        if (sptd_sb.sptd.ScsiStatus == STATUS_GOOD) {
            return 1;
        }
        // Store the sense information
        uint8_t sk = sptd_sb.SenseBuf[2] & 0x0F;  //Sense key is only the lower 4 bits
        uint8_t asc = sptd_sb.SenseBuf[12];
        uint8_t ascq = sptd_sb.SenseBuf[13];
        fprintf(stderr, "SCSI command 0x%02X returns SK/ASC/ASCQ %02X/%02X/%02X", cmd[0], sk, asc, ascq);
    }
    return 0;
}

int MMC_report_key(MMC* mmc, uint8_t agid, uint8_t key_format, uint8_t *buffer, uint16_t length) {
    uint8_t cmd[CDB_SIZE] = {0};
    if (buffer != NULL) {
        memset(buffer, 0, length);
    }

    // REPORT KEY
    cmd[0] = 0xA4;
    // Key Class
    cmd[7] = 0x02;
    // Allocation Length
    cmd[8] = (length >> 8) & 0xFF;
    cmd[9] = length & 0xFF;
    // AGID and Key Format
    cmd[10] = (agid << 6) | (key_format & 0x3F);

    return _sendCmd(mmc->handle, cmd, buffer, 0, length);
}

int MMC_send_key(MMC* mmc, uint8_t agid, uint8_t key_format, uint8_t *buffer, uint16_t length) {
    uint8_t cmd[CDB_SIZE] = {0};

    // SEND KEY
    cmd[0] = 0xA3;
    // Key Class
    cmd[7] = 0x02;
    // Allocation Length
    cmd[8] = (length >> 8) & 0xFF;
    cmd[9] = length & 0xFF;
    // AGID and Key Format
    cmd[10] = (agid << 6) | (key_format & 0x3F);

    return _sendCmd(mmc->handle, cmd, buffer, length, 0);
}
