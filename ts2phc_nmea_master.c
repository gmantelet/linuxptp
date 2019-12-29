/**
 * @file ts2phc_nmea_master.c
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "print.h"
#include "missing.h"
#include "nmea.h"
#include "serial.h"
#include "sock.h"
#include "tmv.h"
#include "ts2phc_master_private.h"
#include "ts2phc_nmea_master.h"
#include "util.h"

#define BAUD		9600
#define NMEA_TMO	2000 /*milliseconds*/

struct ts2phc_nmea_master {
	struct ts2phc_master master;
	struct config *config;
	pthread_t worker;
	/* Protects anonymous struct fields, below, from concurrent access. */
	pthread_mutex_t mutex;
	struct {
		struct timespec local_monotime;
		struct timespec local_utctime;
		struct timespec rmc_utctime;
		int tai_offset;
	};
};

static int open_nmea_connection(const char *host, const char *port,
				const char *serialport)
{
	int fd;

	if (host[0] && port[0]) {
		fd = sock_open(host, port);
		if (fd == -1) {
			pr_err("failed to open nmea source %s:%s", host, port);
		}
		return fd;
	}
	fd = serial_open(serialport, BAUD, 0, 0);
	if (fd == -1) {
		pr_err("failed to open nmea source %s", serialport);
	}
	return fd;
}

static void *monitor_nmea_status(void *arg)
{
	struct nmea_parser *np = nmea_parser_create();
	struct pollfd pfd = { -1, POLLIN | POLLPRI };
	char *host, input[256], *port, *ptr, *uart;
	struct ts2phc_nmea_master *master = arg;
	struct timespec rxtime, tmo = { 2, 0 };
	int cnt, num, parsed;
	struct nmea_rmc rmc;
	struct timex ntx;

	if (!np) {
		pr_err("failed to create NMEA parser");
		return NULL;
	}
	host = config_get_string(master->config, NULL, "ts2phc.nmea_remote_host");
	port = config_get_string(master->config, NULL, "ts2phc.nmea_remote_port");
	uart = config_get_string(master->config, NULL, "ts2phc.nmea_serialport");
	memset(&ntx, 0, sizeof(ntx));
	ntx.modes = ADJ_NANO;

	while (is_running()) {
		if (pfd.fd == -1) {
			pfd.fd = open_nmea_connection(host, port, uart);
			if (pfd.fd == -1) {
				clock_nanosleep(CLOCK_MONOTONIC, 0, &tmo, NULL);
				continue;
			}
		}
		num = poll(&pfd, 1, NMEA_TMO);
		clock_gettime(CLOCK_MONOTONIC, &rxtime);
		adjtimex(&ntx);
		if (num < 0) {
			pr_err("poll failed");
			break;
		}
		if (!num) {
			pr_err("nmea source timed out");
			close(pfd.fd);
			pfd.fd = -1;
			continue;
		}
		if (pfd.revents & POLLERR) {
			pr_err("nmea source socket error");
			close(pfd.fd);
			pfd.fd = -1;
			continue;
		}
		if (!(pfd.revents & (POLLIN | POLLPRI))) {
			continue;
		}
		cnt = read(pfd.fd, input, sizeof(input));
		if (cnt < 0) {
			pr_err("failed to read from nmea source");
			close(pfd.fd);
			pfd.fd = -1;
			continue;
		}
		ptr = input;
		do {
			if (!nmea_parse(np, ptr, cnt, &rmc, &parsed)) {
				// TODO - check rmc.fix_valid
				pthread_mutex_lock(&master->mutex);
				master->local_monotime = rxtime;
				master->local_utctime.tv_sec = ntx.time.tv_sec;
				master->local_utctime.tv_nsec = ntx.time.tv_usec;
				master->rmc_utctime = rmc.ts;
				pthread_mutex_unlock(&master->mutex);
				// TODO - Find a way to get the offset from the GPS.
				master->tai_offset = ntx.tai;
			}
			cnt -= parsed;
			ptr += parsed;
		} while (cnt);
	}

	nmea_parser_destroy(np);
	if (pfd.fd != -1) {
		close(pfd.fd);
	}
	return NULL;
}

static void ts2phc_nmea_master_destroy(struct ts2phc_master *master)
{
	struct ts2phc_nmea_master *m =
		container_of(master, struct ts2phc_nmea_master, master);
	pthread_join(m->worker, NULL);
	free(m);
}

static int ts2phc_nmea_master_getppstime(struct ts2phc_master *master,
					 struct timespec *ts)
{
	struct ts2phc_nmea_master *m =
		container_of(master, struct ts2phc_nmea_master, master);
	tmv_t delay_t1, delay_t2, local_t1, local_t2, rmc;
	struct timespec now;
	int tai_offset;

	clock_gettime(CLOCK_MONOTONIC, &now);
	local_t2 = timespec_to_tmv(now);

	pthread_mutex_lock(&m->mutex);

	local_t1 = timespec_to_tmv(m->local_monotime);
	delay_t2 = timespec_to_tmv(m->local_utctime);
	rmc = timespec_to_tmv(m->rmc_utctime);
	tai_offset = m->tai_offset;

	pthread_mutex_unlock(&m->mutex);

	delay_t1 = rmc;
	pr_debug("nmea delay: %" PRId64 " ns",
		 tmv_to_nanoseconds(tmv_sub(delay_t2, delay_t1)));

	rmc = tmv_add(rmc, tmv_sub(local_t2, local_t1));
	*ts = tmv_to_timespec(rmc);
	ts->tv_sec += tai_offset;

	return 0;
}

struct ts2phc_master *ts2phc_nmea_master_create(struct config *cfg, const char *dev)
{
	struct ts2phc_nmea_master *master;
	int err;

	master = calloc(1, sizeof(*master));
	if (!master) {
		return NULL;
	}
	master->master.destroy = ts2phc_nmea_master_destroy;
	master->master.getppstime = ts2phc_nmea_master_getppstime;
	master->config = cfg;
	err = pthread_create(&master->worker, NULL, monitor_nmea_status, master);
	if (err) {
		pr_err("failed to create worker thread: %s", strerror(err));
		free(master);
		return NULL;
	}
	pthread_mutex_init(&master->mutex, NULL);

	return &master->master;
}
