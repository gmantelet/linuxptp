#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <semaphore.h>
#include <string.h>
#include <linux/kernel.h>

#include <sodium.h>

#include "key.h"
#include "print.h"

#define KEY_LENGTH 65

static struct key_store ks;


static struct key dummy_key;


static void print2(int level, char const *format, ...)
{
	struct timespec ts;
	va_list ap;
	char buf[1024];
	FILE *f;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	va_start(ap, format);
	vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);

	f = level >= LOG_NOTICE ? stdout : stderr;
	fprintf(f, "%s", buf);
	fflush(f);
}


static void hexDump (const char * desc, const void * addr, const int len) {
    int i;
    unsigned char buff[17];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL)
        print2(LOG_INFO, "%s:\n", desc);

    // Length checks.

    if (len == 0) {
        print2(LOG_INFO, "  ZERO LENGTH\n");
        return;
    }
    else if (len < 0) {
        print2(LOG_INFO, "  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Don't print ASCII buffer for the "zeroth" line.

            if (i != 0)
                print2(LOG_INFO, "  %s\n", buff);

            // Output the offset.

            print2(LOG_INFO, "  %04x ", i);
        }

        // Now the hex code for the specific character.
        print2(LOG_INFO, " %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.

    while ((i % 16) != 0) {
        print2(LOG_INFO, "   ");
        i++;
    }

    // And print the final ASCII buffer.

    print2(LOG_INFO, "  %s\n", buff);
}


int init_keystore(void)
{
    if (sodium_init() == -1)
        return 1;

    dummy_key.key_id = 255;
    dummy_key.algorithm_id = 2;
    for (int i=0; i<32; i++)
        dummy_key.security_key[i] = 0x5A;

    return 0;
}

static int warns_once = 0;

void generate_icv(const unsigned char *msg, int msg_len, unsigned char *icv, unsigned char *key)
{
    if (key == NULL)
    {
        if (!warns_once)
        {
            pr_warning("dude, you're using a dummy key");
            warns_once = 1;
        }
        key = dummy_key.security_key;
    }

    crypto_auth_hmacsha256(icv, msg, msg_len, key);

    // msg_print((struct ptp_message *)msg, stdout);
    // hexDump("MSG", msg, msg_len); 
    // hexDump("ICV", icv, 32);

    //pr_info("ICV: %2x %2x %2x %2x %2x %2x %2x %2x ", icv[0], icv[1], icv[2], icv[3], icv[4], icv[5], icv[6], icv[7]);

    // DEBUG - Check ICV with trusted source
    // unsigned char test[] = {0x12, 0x02, 0x00, 0x52, 0x00, 0x00, 0x82, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //                         0x00, 0x00, 0x00, 0x00, 0x3C, 0xCA, 0x87, 0xFF, 0xFE, 0x00, 0xB7, 0xB0, 0x00, 0x03, 0xCE, 0x48, 
    //                         0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    //                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x18, 0xB1, 0x5E, 0x00, 0x0A, 0xFF, 0xFF, 
    //                         0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    //                         0x00, 0x00};
    // 
    // crypto_auth_hmacsha256(icv, test, 82, key);
    // hexDump("DUMMY MSG", test, 82);    
    // hexDump("DUMMY KEY", key, 32);
    // hexDump("DUMMY ICV", icv, 32);
}

int validate_icv(const unsigned char *msg, int msg_len, unsigned char *icv, unsigned char *key)
{
    int ret = 0;

    if (key == NULL)
        key = dummy_key.security_key;

    unsigned char tmp[16];
    memcpy(tmp, icv, 16);
    memset(icv, 0, 16);

    unsigned char hmac[32];
    crypto_auth_hmacsha256(hmac, msg, msg_len, key);

    if ((ret = memcmp(tmp, hmac, 16)))
    {
        //pr_info("Obtained: %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x", tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7], tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14], tmp[15]);    
        //pr_info("Computed: %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x", hmac[0], hmac[1], hmac[2], hmac[3], hmac[4], hmac[5], hmac[6], hmac[7], hmac[9], hmac[10], hmac[11], hmac[12], hmac[13], hmac[14], hmac[15], hmac[16]);

        hexDump ("Obtained ICV", tmp, 16);
        hexDump ("Computed ICV", hmac, 32);
        hexDump ("Received PTP message", msg, msg_len);
        pr_info(" ");
    }

    return ret;
}

struct key* get_key(UInteger16 key_id)
{
    struct key *k = NULL;

    for (k = ks.key_head.lh_first; k != NULL; k = k->key_entries.le_next)
    {
        if (k->key_id)
            return k;
    }

    return NULL;
}

void fetch_key(void)
{
    int fd = shm_open("shm_keystore", O_RDONLY, 0x0644);
    if (fd < 0)
    {
        pr_err("Failed to reach out keystore");
        return;
    }

    caddr_t memptr = mmap(NULL, 1024, PROT_READ, MAP_PRIVATE, fd, 0);
    if ((caddr_t) -1 == memptr)
    {
        pr_err("Failed to map keystore");
        return;
    }

    sem_t* semptr = sem_open("sem_keystore", O_CREAT, 0x644, 0);
    if (semptr == (void*) -1)
    {
        pr_err("Failed to synchronize to keystore");
        return;
    }

    char buf[KEY_LENGTH];
    if (!sem_wait(semptr))
    {
        int i;
        for (i = 0; i < KEY_LENGTH; i++)
            buf[i] = (char) (*(memptr + i));
        sem_post(semptr);
    }

    struct key *k, *kp, *kl;
    if ((k = malloc(sizeof(struct key))) == NULL)
    {
        pr_err("no more memory for key");
        return;
    }

    memcpy(k, buf, KEY_LENGTH);

    if (ks.key_head.lh_first == NULL)
        LIST_INSERT_HEAD(&(ks.key_head), k, key_entries);
    else
        for (kp = ks.key_head.lh_first; kp != NULL; kp = kp->key_entries.le_next)
            kl = kp;

        LIST_INSERT_AFTER(kl, kp, key_entries);


    munmap(memptr, 1024);
    close(fd);
    sem_close(semptr);
    unlink("shm_keystore");
}
