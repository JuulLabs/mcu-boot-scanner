#include <sys/types.h>
#include <sys/uio.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "image.h"

static int verbose = 0;
static int input_fd = STDIN_FILENO;

static void usage()
{
    printf("\nReads an McuBoot image from stdin and dumps the header and TLV data.\n");
    printf("See https://github.com/mcu-tools/mcuboot/blob/main/docs/design.md for details.\n\n");
    printf("Usage: mcuscanner -f <format> [-v]\n");
    printf(" -v : verbose output\n");
    exit(1);
}

static void sig_handler(int signo)
{
    signal(signo, SIG_IGN);
    fprintf(stderr, "Interrupted\n");
    exit(1);
}

static size_t readBytes(void *buf, size_t len) {
    size_t bytes_read = 0;
    int rc = -1;
    char *dest = buf;
    while (bytes_read < len && rc != 0) {
        rc = read(input_fd, dest, len - bytes_read);
        if (rc < 0) {
            perror("Read error");
            exit(1);
        }
        bytes_read += rc;
        if (rc == 0 && bytes_read < len) {
            if (verbose) {
                printf("Wanted %ld bytes but reached end of file after %ld bytes\n", len, bytes_read);
            }
        }
    }
    return bytes_read;
}

static void skipBytes(size_t len) {
    size_t bytes_read = 0;
    char buf[8192];
    while (len > 0) {
        size_t num_to_read = sizeof(buf);
        if (len < num_to_read) {
            num_to_read = len;
        }
        int rc = read(input_fd, buf, num_to_read);
        if (rc < 0) {
            perror("Read error");
            exit(1);
        }
        len -= rc;
        if (rc == 0 && len > 0) {
            fprintf(stderr, "Unexpected EOF\n");
            exit(1);
        }
    }
}


static int isLegacy(struct image_header *header) {
    return header->ih_magic == IMAGE_MAGIC_V1;
}

static void dump_header_flags(uint32_t flags) {
    if (flags & IMAGE_F_ENCRYPTED_AES128) {
        printf(" ENCRYPTED(AES128)");
    } else if (flags & IMAGE_F_ENCRYPTED_AES256) {
        printf(" ENCRYPTED(AES256)");
    }
}

static void dump_header(struct image_header *header) {
    printf("HEADER:\n");
    printf("  Magic: 0x%x (isLegacy = %s)\n", header->ih_magic, isLegacy(header) ? "true" : "false");
    printf("  Load address: 0x%x\n", header->ih_load_addr);
    printf("  Header size: 0x%x (%d bytes)\n", header->ih_hdr_size, header->ih_hdr_size);
    printf("  Protected TLV size: 0x%x (%d bytes)\n", header->ih_protect_tlv_size, header->ih_protect_tlv_size);
    printf("  Image size: 0x%x (%d bytes)\n", header->ih_img_size, header->ih_img_size);

    printf("  Flags: 0x%x", header->ih_flags);
    dump_header_flags(header->ih_flags);
    printf("\n");

    struct image_version *v = &header->ih_ver;
    printf("  Version: %d.%d.%d-%d\n", v->iv_major, v->iv_minor, v->iv_revision, v->iv_build_num);
}

static void verify_header(struct image_header *header) {
    if (header->ih_magic != IMAGE_MAGIC && header->ih_magic != IMAGE_MAGIC_V1) {
        fprintf(stderr, "Bad header magic 0x%x\n", header->ih_magic);
        exit(1);
    }
    // if (header->ih_hdr_size != IMAGE_HEADER_SIZE) {
    //     fprintf(stderr, "Unsupported header size got %d expected %d\n", header->ih_hdr_size, IMAGE_HEADER_SIZE);
    //     exit(1);
    // }
}


static int isProtected(struct image_tlv_info *tlv_info) {
    return tlv_info->it_magic == IMAGE_TLV_PROT_INFO_MAGIC;
}

static void dump_tlv_info(struct image_tlv_info *tlv_info) {
    printf("%sPROTECTED TLV INFO HEADER:\n", isProtected(tlv_info) ? "" : "UN");
    printf("  Magic: 0x%x (isProtected = %s)\n", tlv_info->it_magic, isProtected(tlv_info) ? "true" : "false");
    printf("  Total size (including this header): 0x%x (%d bytes)\n", tlv_info->it_tlv_tot, tlv_info->it_tlv_tot);
}

static void verify_tlv_info(struct image_tlv_info *tlv_info) {
    if (tlv_info->it_magic != IMAGE_TLV_INFO_MAGIC && tlv_info->it_magic != IMAGE_TLV_PROT_INFO_MAGIC) {
        fprintf(stderr, "Bad TLV magic 0x%x\n", tlv_info->it_magic);
        exit(1);
    }
}


static char *tlv_type(uint8_t type) {
    if (type & IMAGE_TLV_KEYHASH) {
        return "Hash of the public key";
    }
    if (type & IMAGE_TLV_SHA256) {
        return "SHA256 of image hdr and body";
    }
    if (type & IMAGE_TLV_RSA2048_PSS) {
        return "RSA2048 of hash output";
    }
    if (type & IMAGE_TLV_ECDSA224) {
        return "ECDSA of hash output - Not supported anymore";
    }
    if (type & IMAGE_TLV_ECDSA_SIG) {
        return "ECDSA of hash output";
    }
    if (type & IMAGE_TLV_RSA3072_PSS) {
        return "RSA3072 of hash output";
    }
    if (type & IMAGE_TLV_ED25519) {
        return "ED25519 of hash output";
    }
    if (type & IMAGE_TLV_ENC_RSA2048) {
        return "Key encrypted with RSA-OAEP-2048";
    }
    if (type & IMAGE_TLV_ENC_KW) {
        return "Key encrypted with AES-KW-128 or 256";
    }
    if (type & IMAGE_TLV_ENC_EC256) {
        return "Key encrypted with ECIES-P256";
    }
    if (type & IMAGE_TLV_ENC_X25519) {
        return "Key encrypted with ECIES-X25519";
    }
    if (type & IMAGE_TLV_DEPENDENCY) {
        return "Image depends on other image";
    }
    if (type & IMAGE_TLV_SEC_CNT) {
        return "Security counter";
    }
    return "unknown";
}

static void dump_tlv_entry(struct image_tlv *tlv, int isProtected) {
    printf("%sPROTECTED TLV ENTRY:\n", isProtected ? "" : "UN");
    printf("  Type: 0x%x (%s)\n", tlv->it_type, tlv_type(tlv->it_type));
    printf("  Size: 0x%x (%d bytes)\n", tlv->it_len, tlv->it_len);
}

static void dump_tlv_entry_data(unsigned char *data, int len) {
    printf("  Data: ");
    while (len-- > 0) {
        printf("%x", *data++);
    }
    printf("\n");
}

// Pass total_size = -1 for unlimited
static void dump_tlv_entries(int total_size, int isProtected) {
    unsigned char data_buf[65535];
    int bytes_read = 0;
    struct image_tlv tlv;
    size_t tlv_entry_size_read = readBytes(&tlv, sizeof(tlv));
    while (tlv_entry_size_read == sizeof(tlv) && bytes_read < total_size) {
        bytes_read += tlv_entry_size_read;
        dump_tlv_entry(&tlv, isProtected);
        if (readBytes(data_buf, tlv.it_len) != tlv.it_len) {
            fprintf(stderr, "Error reading %d bytes of TLV data\n", tlv.it_len);
            exit(1);
        }
        bytes_read += tlv.it_len;
        dump_tlv_entry_data(data_buf, tlv.it_len);
        if (total_size == -1 || bytes_read < total_size) {
            tlv_entry_size_read = readBytes(&tlv, sizeof(tlv));
        }
    }
}

int main(int argc, char *argv[]) {
    int opt;
    while((opt = getopt(argc, argv, "v")) != -1)
    {
        switch(opt)
        {
            case 'v':
                verbose = 1;
                break;
            case ':':
                fprintf(stderr, "parameter required for option -%c\n", optopt);
                usage();
                break;
            default:
                usage();
                break;
        }
    }

    if ((signal(SIGINT, sig_handler) == SIG_ERR) ||
        (signal(SIGTERM, sig_handler) == SIG_ERR))
    {
        perror("Error installing signal handler");
        exit(1);
    }

    struct image_header header;
    readBytes(&header, sizeof(header));
    dump_header(&header);
    verify_header(&header);

    if (header.ih_hdr_size > sizeof(header)) {
        int bytes_to_skip = header.ih_hdr_size - sizeof(header);
        if (verbose) {
            printf("Skipping %d additional header bytes\n", bytes_to_skip);
        }
        skipBytes(bytes_to_skip);
    }

    skipBytes(header.ih_img_size);
    printf("IMAGE BINARY: %d bytes\n", header.ih_img_size);

    if (isLegacy(&header)) {
        printf("TLV INFO HEADER: none - is legacy format\n");
        // Legacy format has no leading info section, we just read trailer entries until EOF
        dump_tlv_entries(-1, 0);
        return 0;
    }

    struct image_tlv_info tlv_info;
    int tlv_info_bytes_read = readBytes(&tlv_info, sizeof(tlv_info));
    dump_tlv_info(&tlv_info);
    verify_tlv_info(&tlv_info);

    if (header.ih_protect_tlv_size > 0) {
        int protected_tlv_byte_count = header.ih_protect_tlv_size - sizeof(tlv_info);
        dump_tlv_entries(protected_tlv_byte_count, 1);
        int unprotected_tlv_byte_count = tlv_info.it_tlv_tot - header.ih_protect_tlv_size;
        if (unprotected_tlv_byte_count > 0) {
            dump_tlv_entries(unprotected_tlv_byte_count, 0);
        }
    } else {
        dump_tlv_entries(tlv_info.it_tlv_tot - sizeof(tlv_info), 0);
    }

    tlv_info_bytes_read = readBytes(&tlv_info, sizeof(tlv_info));
    while (tlv_info_bytes_read == sizeof(tlv_info)) {
        dump_tlv_info(&tlv_info);
        verify_tlv_info(&tlv_info);
        dump_tlv_entries(tlv_info.it_tlv_tot - sizeof(tlv_info), 0);
        tlv_info_bytes_read = readBytes(&tlv_info, sizeof(tlv_info));
    }

    printf("END\n");
    return 0;
}
