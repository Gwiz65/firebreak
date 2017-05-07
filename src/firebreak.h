/******************************************************************************
 * firebreak.h                                                                *
 *                                                                            *
 * Copyright (C) 2017 Gwiz <gwiz65@gmail.com>                                 *
 *                                                                            *
 * firebreak is free software: you can redistribute it and/or modify it       *
 * under the terms of the GNU General Public License as published by the      *
 * Free Software Foundation, either version 3 of the License, or              *
 * (at your option) any later version.                                        *
 *                                                                            *
 * firebreak is distributed in the hope that it will be useful, but           *
 * WITHOUT ANY WARRANTY; without even the implied warranty of                 *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                       *
 * See the GNU General Public License for more details.                       *
 *                                                                            *
 * You should have received a copy of the GNU General Public License along    *
 * with this program.  If not, see <http://www.gnu.org/licenses/>.            *
 *                                                                            *
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h> 
#include <time.h> 
#include <sys/stat.h>
#include <sys/wait.h>

#include <arpa/inet.h>			//Provides ntohs/htons
#include <netinet/udp.h>   		//Provides declarations for udp header
#include <netinet/tcp.h>   		//Provides declarations for tcp header
#include <netinet/ip.h>    		//Provides declarations for ip header
#include <netinet/ip6.h>    	//Provides declarations for ip6 header
#include <linux/if_ether.h>  	//For ethernet types
#include <net/ethernet.h> 		//For ether_header

/****************************
 *         Defines          *
 ****************************/
// Local or system ui file
#define UI_FILE PACKAGE_DATA_DIR"/ui/firebreak.ui"
//#define UI_FILE "src/firebreak.ui"

#define MAXDEVICES 6	// max number of network devices

/****************************
 *        Structures        *
 ****************************/
// structure to hold device info
typedef struct dev_info {
	char		name[256];
	uint8_t		mac[6];
}dev_info_t;

// structure to hold ports we've seen already
typedef struct existing_ports {
	uint16_t	port;
	uint32_t	pid;
}existing_ports_t;

// message structure 
typedef struct fb_message {
	int				type;  
	// 1=RECD,IPv4,TCP 2=SENT,IPv4,TCP, 3=RECD,IPv4,UDP 4=SENT,IPv4,UDP
	// 5=RECD,IPv6,TCP 6=SENT,IPv6,TCP, 7=RECD,IPv6,UDP 8=SENT,IPv6,UDP
	char			devname[256];
	//uint8_t			devmac[6];
	int				data_size;
	//uint16_t		locport;
	uint32_t		pid;
	unsigned char   address[16];
	uint16_t		port;
}fb_message_t;

// Connection Info structure
typedef struct fb_connectioninfo {

	int				type;  // 0 = *unused* 1=TCP 2=UDP
	char			devname[256];
	uint32_t        data_recd;
	uint32_t        data_sent;
	uint32_t		pid;
	char			program[256];
	unsigned char   address[16];
	char			addressstring[INET6_ADDRSTRLEN];
	uint16_t		port;
	time_t			firstseen;
	time_t			lastseen;
}fb_connectioninfo_t;

