/* Arcan-fe (OS/device platform), scriptable front-end engine
 *
 * Arcan-fe is the legal property of its developers, please refer
 * to the platform/LICENSE file distributed with this source distribution
 * for licensing terms.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include <arcan_math.h>
#include <arcan_general.h>

int arcan_sem_post(sem_handle sem)
{
	return sem_post(sem);
}

int arcan_sem_unlink(sem_handle sem, char* key)
{
	return sem_unlink(key);
}

int arcan_sem_trywait(sem_handle sem)
{
	return sem_trywait(sem);
}

int arcan_sem_wait(sem_handle sem)
{
	return sem_wait(sem);
}

int arcan_sem_init(sem_t** sem, int val)
{
	if (*sem == NULL){
		*sem = malloc(sizeof(sem_t));
	}
	return sem_init(*sem, 0, val); 
}

int arcan_sem_destroy(sem_handle sem)
{
	return sem_destroy(sem);
}
