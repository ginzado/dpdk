/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Ginzado Co., Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>

#define GPWSTATS_UNIX_SOCKET_PATH "/run/gpwstats.socket"

typedef unsigned long long int uint64_t;

struct gpwstats {
	uint64_t ul_rx_packets;
	uint64_t ul_rx_bytes;
	uint64_t ul_rx_bpdus;
	uint64_t ul_tx_packets;
	uint64_t ul_tx_bytes;
	uint64_t ul_tx_errors;
	uint64_t dl_rx_packets;
	uint64_t dl_rx_bytes;
	uint64_t dl_rx_bpdus;
	uint64_t dl_tx_packets;
	uint64_t dl_tx_bytes;
	uint64_t dl_tx_errors;
};

int
main(void) {
	int ret;
	struct sockaddr_un clientsa;

	int clientfd;

	memset(&clientsa, 0, sizeof(clientsa));

	clientfd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (clientfd < 0) {
		printf("socket failed\n");
		exit(-1);
	}

	clientsa.sun_family = AF_LOCAL;
	strcpy(clientsa.sun_path, GPWSTATS_UNIX_SOCKET_PATH);

	ret = connect(clientfd, (struct sockaddr *)&clientsa, sizeof(clientsa));
	if (ret < 0) {
		printf("connect failed\n");
		close(clientfd);
		exit(-1);
	}

	int req = 0;
	ret = send(clientfd, &req, sizeof(req), 0);
	if (ret != sizeof(req)) {
		printf("send failed\n");
		close(clientfd);
		exit(-1);
	}

	struct gpwstats gpwstats;
	ret = recv(clientfd, &gpwstats, sizeof(gpwstats), 0);
	if (ret != sizeof(gpwstats)) {
		printf("recv failed\n");
		close(clientfd);
		exit(-1);
	}

	printf("gpwstats.ul_rx_packets %20lld\n", gpwstats.ul_rx_packets);
	printf("gpwstats.ul_rx_bytes   %20lld\n", gpwstats.ul_rx_bytes);
	printf("gpwstats.ul_rx_bpdus   %20lld\n", gpwstats.ul_rx_bpdus);
	printf("gpwstats.ul_tx_packets %20lld\n", gpwstats.ul_tx_packets);
	printf("gpwstats.ul_tx_bytes   %20lld\n", gpwstats.ul_tx_bytes);
	printf("gpwstats.ul_tx_errors  %20lld\n", gpwstats.ul_tx_errors);
	printf("gpwstats.dl_rx_packets %20lld\n", gpwstats.dl_rx_packets);
	printf("gpwstats.dl_rx_bytes   %20lld\n", gpwstats.dl_rx_bytes);
	printf("gpwstats.dl_rx_bpdus   %20lld\n", gpwstats.dl_rx_bpdus);
	printf("gpwstats.dl_tx_packets %20lld\n", gpwstats.dl_tx_packets);
	printf("gpwstats.dl_tx_bytes   %20lld\n", gpwstats.dl_tx_bytes);
	printf("gpwstats.dl_tx_errors  %20lld\n", gpwstats.dl_tx_errors);

	close(clientfd);

	return 0;
}
