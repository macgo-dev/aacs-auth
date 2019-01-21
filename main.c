#include <unistd.h>
#include <memory.h>

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/aes.h>

#include "mmc.h"

static EC_GROUP* AACS_EC_Group() {
    static EC_GROUP* group = NULL;
    if (!group) {
        BIGNUM *p = NULL, *a = NULL, *b = NULL, *r = NULL, *gx = NULL, *gy = NULL, *co = NULL;
        BN_dec2bn(&p, "900812823637587646514106462588455890498729007071");
        BN_dec2bn(&a, "-3");
        BN_dec2bn(&b, "366394034647231750324370400222002566844354703832");
        group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
        BN_free(p);
        BN_free(a);
        BN_free(b);
        BN_dec2bn(&r, "900812823637587646514106555566573588779770753047");
        BN_dec2bn(&gx, "264865613959729647018113670854605162895977008838");
        BN_dec2bn(&gy, "51841075954883162510413392745168936296187808697");
        BN_dec2bn(&co, "1");
        EC_POINT* g = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates_GFp(group, g, gx, gy, NULL);
        EC_GROUP_set_generator(group, g, r, co);
        EC_POINT_free(g);
        BN_free(r);
        BN_free(gx);
        BN_free(gy);
        BN_free(co);
    }
    return group;
}

static int AACS_Check(const uint8_t *pubkey, const uint8_t *privkey) {
    BIGNUM *px = BN_bin2bn(pubkey,    20, NULL);
    BIGNUM *py = BN_bin2bn(pubkey+20, 20, NULL);
    BIGNUM *p  = BN_bin2bn(privkey, 20, NULL);

    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, AACS_EC_Group());
    EC_KEY_set_public_key_affine_coordinates(key, px, py);
    EC_KEY_set_private_key(key, p);

    int ret = EC_KEY_check_key(key);

    EC_KEY_free(key);
    BN_free(px);
    BN_free(py);
    BN_free(p);

    return ret == 1;
}

static int AACS_Verify(const uint8_t *pubkey, const uint8_t* signature, const uint8_t* msg, size_t size) {
    uint8_t md[SHA_DIGEST_LENGTH];
    SHA1(msg, size, md);

    BIGNUM *px = BN_bin2bn(pubkey,    20, NULL);
    BIGNUM *py = BN_bin2bn(pubkey+20, 20, NULL);

    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, AACS_EC_Group());
    EC_KEY_set_public_key_affine_coordinates(key, px, py);

    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(signature,    20, NULL);
    BIGNUM *s = BN_bin2bn(signature+20, 20, NULL);
    ECDSA_SIG_set0(sig, r, s);

    int ret = ECDSA_do_verify(md, sizeof(md), sig, key);

    EC_KEY_free(key);
    ECDSA_SIG_free(sig);
    BN_free(px);
    BN_free(py);

    return ret == 1;
}

static int AACS_Sign(const uint8_t *privkey, uint8_t* signature, const uint8_t* msg, size_t size) {
    uint8_t md[SHA_DIGEST_LENGTH];
    SHA1(msg, size, md);

    BIGNUM *p = BN_bin2bn(privkey, 20, NULL);

    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, AACS_EC_Group());
    EC_KEY_set_private_key(key, p);

    ECDSA_SIG* sig = ECDSA_do_sign(md, sizeof(md), key);

    const BIGNUM *pr, *ps;
    ECDSA_SIG_get0(sig, &pr, &ps);
    memset(signature, 0, 40);
    BN_bn2bin(pr, &signature[20 - BN_num_bytes(pr)]);
    BN_bn2bin(ps, &signature[40 - BN_num_bytes(ps)]);

    EC_KEY_free(key);
    ECDSA_SIG_free(sig);
    BN_free(p);

    return 1;
}

static int AACS_Verify_LApub(const uint8_t* signature, const uint8_t* msg, size_t size) {
    uint8_t point[] = {
            0x63, 0xC2, 0x1D, 0xFF, 0xB2, 0xB2, 0x79, 0x8A, 0x13, 0xB5,
            0x8D, 0x61, 0x16, 0x6C, 0x4E, 0x4A, 0xAC, 0x8A, 0x07, 0x72,

            0x13, 0x7E, 0xC6, 0x38, 0x81, 0x8F, 0xD9, 0x8F, 0xA4, 0xC3,
            0x0B, 0x99, 0x67, 0x28, 0xBF, 0x4B, 0x91, 0x7F, 0x6A, 0x27
    };
    return AACS_Verify(point, signature, msg, size);
}


static int aacs_auth(MMC* mmc, const uint8_t* host_cert, const uint8_t* host_privkey) {
    int ok = 0;
    uint8_t agid = 0;
    uint8_t drive_cert[92], drive_nonce[20], host_nonce[20], drive_point[40], drive_sig[40], host_sig[40];

    if (!MMC_report_agid(mmc, &agid)) {
        for (int i=0; i<4; i++)
            MMC_invalidate_agid(mmc, i);
        if (!MMC_report_agid(mmc, &agid)) {
            fprintf(stderr, "Unable to acquire an AGID\n");
            return 0;
        }
    }

    RAND_bytes(host_nonce, sizeof(host_nonce));

    if (!MMC_send_host_cert(mmc, agid, host_nonce, host_cert)) {
        fprintf(stderr, "Failed to send host certificate (Host certificate has been revoked?)\n");
        goto err;
    }

    if (!MMC_report_drive_cert(mmc, agid, drive_nonce, drive_cert)) {
        fprintf(stderr, "Failed to get drive certificate\n");
        goto err;
    }

    if (!AACS_Verify_LApub(&drive_cert[92-40], drive_cert, 92-40)) {
        fprintf(stdout, "Drive certificate is invalid\n");
        goto err;
    }

    if (drive_cert[0] != 1) {
        fprintf(stdout, "Drive certificate type: %d\n", drive_cert[0]);
    }
    fprintf(stdout, "Drive certificate ID: %02X%02X%02X%02X%02X%02X\n", drive_cert[4], drive_cert[5], drive_cert[6], drive_cert[7], drive_cert[8], drive_cert[9]);
    fprintf(stdout, "Drive certificate BEC: %s\n", (drive_cert[1] & 1) ? "Yes" : "No");

    if (!MMC_report_drive_Key(mmc, agid, drive_point, drive_sig)) {
        fprintf(stderr, "Failed to get drive key\n");
        goto err;
    }

    uint8_t msg[60];
    memcpy(msg, host_nonce, sizeof(host_nonce));
    memcpy(msg + 20, drive_point, sizeof(drive_point));

    if (!AACS_Verify(&drive_cert[12], drive_sig, msg, sizeof(msg))) {
        fprintf(stderr, "Failed to verify drive key\n");
        goto err;
    }

    if (host_privkey) {
        EC_GROUP* group = AACS_EC_Group();

        BIGNUM* order = BN_new();
        BIGNUM* hostKey = BN_new();
        EC_GROUP_get_order(group, order, NULL);
        BN_rand_range(hostKey, order);
        BN_free(order);

        EC_POINT *hostPoint = EC_POINT_new(group);
        EC_POINT_mul(group, hostPoint, hostKey, NULL, NULL, NULL);
        BN_free(hostKey);

        EC_POINT_point2oct(group, hostPoint, POINT_CONVERSION_UNCOMPRESSED, &msg[60 - 40 - 1], 40 + 1, NULL);
        EC_POINT_free(hostPoint);
        memcpy(msg, drive_nonce, 20);

        AACS_Sign(host_privkey, host_sig, msg, sizeof(msg));

        fprintf(stdout, "Host signature generated\n");

        if (!AACS_Verify(&host_cert[12], host_sig, msg, sizeof(msg))) {
            fprintf(stderr, "Failed to verify host key\n");
            goto err;
        }
        if (!MMC_send_host_key(mmc, agid, &msg[20], host_sig)) {
            fprintf(stderr, "Failed to send host key\n");
            goto err;
        }
    }

    ok = 1;

    err:
    MMC_invalidate_agid(mmc, agid);

    return ok;
}

static void usage();

int main(int argc, char *argv[])
{
    int ch;
    char *cert = NULL, *privkey = NULL;

    while ((ch = getopt(argc, argv, "c:p:")) != -1) {
        switch (ch) {
            case 'c':
                cert = optarg;
                break;
            case 'p':
                privkey = optarg;
                break;
            case '?':
            default:
                usage();
        }
    }

    argc -= optind;
    argv += optind;

    if (!cert || argc != 1) {
        usage();
    }

    BIGNUM *bn_cert = NULL, *bn_privkey = NULL;

    if (BN_hex2bn(&bn_cert, cert) != 92*2) {
        fprintf(stderr, "Incorrect host certificate input\n");
        exit(EXIT_FAILURE);
    }

    if (privkey && BN_hex2bn(&bn_privkey, privkey) != 20*2) {
        fprintf(stderr, "Incorrect host private key input\n");
        exit(EXIT_FAILURE);
    }

    uint8_t host_cert[92] = {0};
    uint8_t host_privkey[20] = {0};

    BN_bn2bin(bn_cert, &host_cert[sizeof(host_cert) - BN_num_bytes(bn_cert)]);
    if (bn_privkey)
        BN_bn2bin(bn_privkey, &host_privkey[sizeof(host_privkey) - BN_num_bytes(bn_privkey)]);

    if (!AACS_Verify_LApub(&host_cert[92-40], host_cert, 92-40)) {
        fprintf(stderr, "Host certificate is invalid\n");
        exit(EXIT_FAILURE);
    }

    if (bn_privkey && !AACS_Check(&host_cert[12], host_privkey)) {
        fprintf(stderr, "Host private key is invalid\n");
        exit(EXIT_FAILURE);
    }

    MMC* mmc = MMC_open(argv[0]);

    if (!mmc) {
        fprintf(stderr, "Unable to open device: %s\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int ok = aacs_auth(mmc, host_cert, bn_privkey ? host_privkey : NULL);

    MMC_close(mmc);

    if (ok) {
        fprintf(stdout, "No issues found during AACS drive authentication\n");
    }

    exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
}

static void usage() {
    fprintf(stderr, "usage: aacs-auth -c certificate [-p private_key] device\n");
    exit(EXIT_FAILURE);
}
