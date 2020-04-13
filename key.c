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


void generate_icv(const unsigned char *msg, int msg_len, unsigned char *icv, unsigned char *key)
{
    char msg[1024];
    char buf[16];

    if (key == NULL)
        key = &dummy_key;

    crypto_auth_hmacsha256_keygen(key);
    crypto_auth_hmacsha256(hash, msg, msg_len, key);

    strcpy(msg,  "ICV: ");
    for (int i=0; i<32; i++)
    {
        strcpy(buf,  "%2x ", icv[i]);
        strcat(msg, buf);
    }
    pr_info(msg)
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
